# chacha20poly1305.tcl --
#
#       Implementation of the ChaCha20-Poly1305 authenticated cipher.
#
# Copyright (c) 2018 Neil Madden.
# License: Tcl-style

package require Tcl         8.6

if {[info exists argv0] && [file tail [info script]] eq [file tail $argv0]} {
    ::tcl::tm::path add [file dirname [info script]]
}

package require chacha20    1.0.0
package require poly1305    1.0.0
package provide chacha20poly1305 1.0.0

namespace eval ::chacha20poly1305 {
    namespace export encrypt decrypt
    namespace ensemble create

    proc genkey {key nonce} {
        set state [chacha20::block [chacha20::initialState $key 0 $nonce] 0]
        binary format i8 $state
    }

    proc encrypt {key message args} {
        array set options {
            -nonce      ""
            -assocdata  ""
        }
        array set options $args
        set nonce $options(-nonce)
        if {[string length $nonce] != 12} {
            error "nonce must be 12 bytes"
        }
        set assocData $options(-assocdata)
        unset options(-assocdata)

        set ciphertext [::chacha20 encrypt $key $message {*}[array get options] -counter 1]
        set tag [mac $key $nonce $assocData $ciphertext]

        return $ciphertext$tag
    }

    proc mac {key nonce assocData ciphertext} {
        set macKey [genkey $key $nonce]
        #puts "subkey = [binary encode hex $macKey]"
        set padding1 [padding $assocData]
        set padding2 [padding $ciphertext]
        set lengths [binary format ww [string length $assocData] [string length $ciphertext]]

        set macInput "$assocData$padding1$ciphertext$padding2$lengths"
        #puts [binary encode hex $macInput]

        return [::poly1305 compute $macKey $macInput]
    }

    proc decrypt {key ciphertext args} {
        array set options {
            -nonce      ""
            -assocdata  ""
        }
        array set options $args
        set nonce $options(-nonce)
        if {[string length $nonce] != 12} {
            error "nonce must be 12 bytes"
        }
        set assocData $options(-assocdata)
        unset options(-assocdata)
    
        set suppliedTag [string range $ciphertext end-15 end]
        set ciphertext [string range $ciphertext 0 end-16]
        set computedTag [mac $key $nonce $assocData $ciphertext]
        
        if {![poly1305::equals $computedTag $suppliedTag]} {
            error "invalid authentication tag"
        }

        return [chacha20 decrypt $key $ciphertext {*}[array get options] -counter 1]
    }

    proc padding {input} {
        set padLen [expr {(16 - ([string length $input] & 15)) & 15}]
        string repeat \x00 $padLen
    }
}

##### TESTS #####
#
if {![info exists argv0] || [file tail [info script]] ne [file tail $argv0]} {
    # Not running as main script so return to avoid running tests below
    return
}

proc fromHex hex {
    regsub -all {\s+} $hex {} hex
    regsub -all {:} $hex {} hex
    regsub -all {..} $hex {\x\0} hex
    subst $hex
}

proc assertEqual {a b {msg ""}} {
    if {$a ne $b} {
        puts "FAIL - assertion failed: expecting '[binary encode hex $a]' to equal '[binary encode hex $b]' $msg"
    } else {
        puts "PASS - $msg"
    }
}

set key [fromHex {80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
                  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f}]
set nonce [fromHex {00 00 00 00 00 01 02 03 04 05 06 07}]

assertEqual [chacha20poly1305::genkey $key $nonce] [fromHex {
    8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
    a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
}] "poly1305 subkey generation"

set message "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
set aad [fromHex {50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7}]
set nonce [fromHex {07 00 00 00 40 41 42 43 44 45 46 47}]

set ctAndTag [chacha20poly1305 encrypt $key $message -assocdata $aad -nonce $nonce]
set ciphertext [string range $ctAndTag 0 end-16]
set tag [string range $ctAndTag end-15 end]

assertEqual $ciphertext [fromHex {
    d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
    a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
    3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
    1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
    92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
    fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
    3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
    61 16 
}] "ChaPoly AEAD - ciphertext test vector"

assertEqual $tag [fromHex {1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91}] "ChaPoly AEAD - authentication tag"

set decrypted [chacha20poly1305 decrypt $key $ctAndTag -assocdata $aad -nonce $nonce]
assertEqual $decrypted $message "ChaPoly AEAD - roundtrip"

# vim: ft=tcl