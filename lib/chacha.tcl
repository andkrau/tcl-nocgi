# chacha.tcl --
#
#       Implementation of the ChaCha20 and XChaCha20 stream ciphers.
#
# Copyright (c) 2018 Neil Madden.
# License: Tcl-style

package require Tcl         8.6
package provide chacha20    1.0.0

# chacha20 encrypt key plaintext ?options...?
# chacha20 decrypt key ciphertext ?options...?
#
#       Encrypts (resp. decrypts) a message using the ChaCha20 cipher as described in
#       RFC 8439.
#
namespace eval ::chacha20 {
    namespace export encrypt decrypt
    namespace ensemble create

    variable INT32 [expr {2**32 - 1}]
    variable RAND_IN ""

    # Bitwise left rotation
    proc rotl {i distance} {
        variable INT32
        expr {(($i << $distance) & $INT32) | (($i & $INT32) >> (32-$distance))}
    }

    # Addition mod 2^32
    proc add32 {a b} {
        variable INT32
        expr {($a + $b) & $INT32}
    }

    # Bitwise exclusive or
    proc xor {a b} { expr {$a ^ $b} }

    # quarterRound stateRef a b c d --
    #
    #   The chacha20 quarter-round (i.e., 4 of these make a full round).
    #   stateRef is the name of a variable containing the chacha20 state (16 32-bit integers)
    #   a b c d are the 4 indices to operate on
    #   The state is mutated in-place
    proc quarterRound {stateRef a b c d} {
        variable INT32
        upvar 1 $stateRef state

        lset state $a [add32 [lindex $state $a] [lindex $state $b]]
        lset state $d [rotl [xor [lindex $state $d] [lindex $state $a]] 16]
        lset state $c [add32 [lindex $state $c] [lindex $state $d]]
        lset state $b [rotl [xor [lindex $state $b] [lindex $state $c]] 12]
        lset state $a [add32 [lindex $state $a] [lindex $state $b]]
        lset state $d [rotl [xor [lindex $state $d] [lindex $state $a]]  8]
        lset state $c [add32 [lindex $state $c] [lindex $state $d]]
        lset state $b [rotl [xor [lindex $state $b] [lindex $state $c]]  7]
    }

    # rounds state ?numRounds? --
    #
    #   Applies the given number of rounds (default: 20) of the chacha20 block function
    #   to the given state, returning the new state.
    #
    proc rounds {state {numRounds 20}} {
        for {set i 0} {$i < ($numRounds / 2)} {incr i} {
            quarterRound state  0  4  8 12
            quarterRound state  1  5  9 13
            quarterRound state  2  6 10 14
            quarterRound state  3  7 11 15
            quarterRound state  0  5 10 15
            quarterRound state  1  6 11 12
            quarterRound state  2  7  8 13
            quarterRound state  3  4  9 14
        }
        return $state
    }

    # Computes the chacha20 initial state for the given key, nonce and block counter
    proc initialState {key blockCounter nonce} {
        binary scan $key i8 keyInts
        binary scan $nonce i3 nonceInts

        # Magic constants
        set state [list 0x61707865 0x3320646e 0x79622d32 0x6b206574]
        lappend state {*}$keyInts
        lappend state $blockCounter
        lappend state {*}$nonceInts

        lmap x $state { expr $x }
    }

    # The chacha20 block function. This applies $numRounds rounds of the chacha20 round
    # function to the initial state and then adds back in the initial state using 32-bit
    # modular addition.
    proc block {initialState counter {numRounds 20}} {

        lset initialState 12 $counter
        #puts "initial state: [hex $initialState]"

        set state [rounds $initialState $numRounds]
        #puts "After 20 rounds: [hex $state]"

        lmap x $initialState y $state { add32 $x $y }
    }

    # rand numBytes --
    #
    #   Reads $numBytes from /dev/urandom. NB: this will fail on Windows.
    #
    proc rand {numBytes} {
        variable RAND_IN
        if {$RAND_IN eq "" || $RAND_IN ni [chan names]} {
            set RAND_IN [open /dev/urandom rb]
        }
        set data [read $RAND_IN $numBytes]
        return $data
    }

    # encrypt key plaintext ?options...? --
    #
    #   Encrypts the plaintext under the given key and nonce, returning the ciphertext.
    #
    # Parameters:
    #   key         - the 32-byte binary key.
    #   plaintext   - the plaintext message to encrypt.
    # Options:
    #   -counter counter    - the initial block counter. Defaults to 0.
    #   -nonce              - the 12-byte binary nonce. MUST be unique for every invocation for the same key.
    #               Defaults to a random value (note: this places a safe limit of around 2^32 invocations with
    #               the same key).
    #   -rounds numRounds   - the number of rounds to apply. Defaults to 20. The eStream project
    #               recommended 12 rounds for speed, and you could go as low as 8, but everybody
    #               uses 20 rounds for security reasons. ChaCha20 is very fast anyway.
    # Returns:
    #   The encrypted ciphertext, of exactly the same length as the plaintext.
    #
    proc encrypt {key plaintext args} {
        array set options {
            -counter        0
            -rounds         20
            -nonce          ""
        }
        array set options $args

        set counter $options(-counter)
        unset options(-counter)

        set rounds $options(-rounds)
        unset options(-rounds)

        set nonce $options(-nonce)
        unset options(-nonce)

        if {[llength [array names options]] != 0} {
            error "unknown option(s): [array names options]"
        }

        if {$nonce eq ""} {
            set nonce [rand 12]
        }

        if {[string length $key] != 32} {
            error "key must be exactly 32 bytes (binary format)"
        }
        if {[string length $nonce] != 12} {
            error "nonce must be exactly 12 bytes (binary format)"
        }
        if {$counter < 0 || $counter > (2**32-1)} {
            error "counter must be in range 0..2^32-1"
        }

        set len [string length $plaintext]
        set numBlocks [expr {$len/64 + 1}]

        set state [initialState $key $counter $nonce]
    
        set ciphertext ""
        for {set i 0} {$i < $numBlocks} {incr i} {
            set start [expr {$i * 64}]
            set end [expr {min($start + 63, $len)}]
            #puts "$start..$end"
            binary scan [string range $plaintext $start $end] c* pt
            #puts "Block $i plaintext: [hex $pt]"
            binary scan [binary format i* [block $state [expr {$counter + $i}] $rounds]] c* keyStream
            #puts "Block $i keystream: [hex $keyStream]"
            set xored [list]
            for {set j 0} {$j < [llength $pt]} {incr j} {
                lappend xored [expr {[lindex $keyStream $j] ^ [lindex $pt $j]}]
            }
            #puts "Block $i ciphered : [hex $xored]"
            append ciphertext [binary format c* $xored]
        }

        return $ciphertext
    }

    # decrypt key nonce ciphertext ?options...? --
    #
    #   Decrypts the ciphertext using the given key and nonce, returning the original plaintext.
    #   NB: As ChaCha20 is a stream cipher, this is the same operation as encryption.
    #
    # Parameters:
    #   key         - the 32-byte binary key.
    #   ciphertext  - the encrypted ciphertext message to decrypt.
    # Options:
    #   -counter counter    - the initial block counter. Defaults to 0.
    #   -nonce              - the 12-byte binary nonce. MUST be unique for every invocation for the same key.
    #               Defaults to a random value (note: this places a safe limit of around 2^32 invocations with
    #               the same key).
    #   -rounds numRounds   - the number of rounds to perform. Defaults to 20.
    # Returns:
    #   The decrypted plaintext message.
    #
    proc decrypt {key ciphertext args} {
        # chacha20 is a stream cipher so encryption == decryption
        encrypt $key $ciphertext {*}$args
    }

    # hex-dump a list of bytes, for debugging
    proc hex values { lmap x $values { format "%02x" [expr {$x & 0xFF}] } }
}

# hchacha20 core key input --
#
#       Hashes the given input under the given key. This is an extremely fast pseudorandom function (PRF)
#       built on top of the chacha20 core round function. It is suitable as a key deriviation function (KDF),
#       as used in XChaCha. Other uses are not recommended (use HMAC if you need a general purpose keyed hash).
#
namespace eval ::hchacha20 {
    namespace export core
    namespace ensemble create

    proc core {key input} {
        if {[string length $key] != 32} {
            error "key must be exactly 32 bytes (binary format)"
        }
        if {[string length $input] != 16} {
            error "input must be exactly 16 bytes"
        }

        binary scan $input i counter
        set state [chacha20::initialState $key $counter [string range $input 4 end]]
        #puts [lmap x $state { format %08x [expr {$x & 0xFFFFFFFF}] }]

        set state [chacha20::rounds $state][unset state]
        #puts [lmap x $state { format %08x [expr {$x & 0xFFFFFFFF}] }]

        binary format i8 [lreplace $state 4 11]
    }
}

# xchacha20 encrypt key plaintext ?options...?
# xchacha20 decrypt key ciphertext ?options...?
#
#       The Xchacha20 "extended nonce" stream cipher. This is a variant of chacha20 that accepts
#       a 24-byte nonce rather than 12 bytes. It is therefore suitable for using randomly generated
#       nonce values, rather than a simple counter or other deterministic nonce. This is useful in
#       situations where it is hard to maintain state for the nonce, for instance when a cluster of
#       servers are sharing the same key. The arguments and options are the same as for ChaCha, except
#       that a 24-byte nonce is used instead of a 12-byte one.
#
namespace eval ::xchacha20 {
    namespace export encrypt decrypt
    namespace ensemble create
    
    proc encrypt {key plaintext args} {
        array set options {
            -nonce      ""
        }
        array set options $args
        set nonce $options(-nonce)
        unset options(-nonce)
        if {$nonce eq ""} {
            set nonce [rand 24]
        }

        if {[string length $key] != 32} {
            error "key must be 32 bytes"
        }
        if {[string length $nonce] != 24} {
            error "nonce must be 24 bytes"
        }
        set subKey [hchacha20 core $key [string range $nonce 0 15]]
        set subNonce \x00\x00\x00\x00[string range $nonce 16 end]
        chacha20 encrypt $subKey $plaintext -nonce $subNonce {*}[array get options]
    }
    
    proc decrypt {key ciphertext args} {
        encrypt $key $ciphertext {*}$args
    }
}

##### TESTS #####

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

# Test vectors from RFC 8439
set key [fromHex {00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f}]
set nonce [fromHex {00:00:00:09:00:00:00:4a:00:00:00:00}]
set counter 1

set initialState [chacha20::initialState $key $counter $nonce]

assertEqual $initialState [lmap x {
       61707865  3320646e  79622d32  6b206574
       03020100  07060504  0b0a0908  0f0e0d0c
       13121110  17161514  1b1a1918  1f1e1d1c
       00000001  09000000  4a000000  00000000
} { expr 0x$x }] "initial state"


assertEqual [chacha20::rounds $initialState] [lmap x {
       837778ab  e238d763  a67ae21e  5950bb2f
       c4f2d0c7  fc62bb2f  8fa018fc  3f5ec7b7
       335271c2  f29489f3  eabda8fc  82e46ebd
       d19c12b4  b04e16de  9e83d0cb  4e3c50a2
} { expr 0x$x }] "after 20 rounds"    

assertEqual [chacha20::block [chacha20::initialState $key $counter $nonce] $counter] [lmap x {
       e4e7f110  15593bd1  1fdd0f50  c47120a3
       c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
       466482d2  09aa9f07  05d7c214  a2028bd9
       d19c12b5  b94e16de  e883d0cb  4e3c50a2
} { expr 0x$x }] "block function"    

set message "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

set key [fromHex {00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f}]
set nonce [fromHex {00:00:00:00:00:00:00:4a:00:00:00:00}]
set counter 1

assertEqual [chacha20 encrypt $key $message -nonce $nonce -counter $counter] [fromHex {
  6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
  e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
  f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
  16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
  07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
  52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
  5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
  87 4d
}] "encrypt"

assertEqual [chacha20 decrypt $key [chacha20 encrypt $key $message -nonce $nonce -counter $counter] -nonce $nonce -counter $counter] $message "roundtrip"

# Additional test vectors from RFC 8439 Appendix A
set key [string repeat \x00 32]
set nonce [string repeat \x00 12]
assertEqual [chacha20::block [chacha20::initialState $key 0 $nonce] 0] [lmap x {
        ade0b876  903df1a0  e56a5d40  28bd8653
        b819d2bd  1aed8da0  ccef36a8  c70d778b
        7c5941da  8d485751  3fe02477  374ad8b8
        f4b8436a  1ca11815  69b687c3  8665eeb2
} { expr 0x$x }] "block function - additional test vector 1"

assertEqual [chacha20::block [chacha20::initialState $key 1 $nonce] 1] [lmap x {
        bee7079f  7a385155  7c97ba98  0d082d73
        a0290fcb  6965e348  3e53c612  ed7aee32
        7621b729  434ee69c  b03371d5  d539d874
        281fed31  45fb0a51  1f0ae1ac  6f4d794b
} { expr 0x$x }] "block function - additional test vector 2"

set key [string repeat \x00 31]\x01
assertEqual [chacha20::block [chacha20::initialState $key 1 $nonce] 1] [lmap x {
        2452eb3a  9249f8ec  8d829d9b  ddd4ceb1
        e8252083  60818b01  f38422b8  5aaa49c9
        bb00ca8e  da3ba7b4  c4b592d1  fdf2732f
        4436274e  2561b3c8  ebdd4aa6  a0136c00
} { expr 0x$x }] "block function - additional test vector 3"

set key \x00\xff[string repeat \x00 30]
assertEqual [chacha20::block [chacha20::initialState $key 2 $nonce] 2] [lmap x {
        fb4dd572  4bc42ef1  df922636  327f1394
        a78dea8f  5e269039  a1bebbc1  caf09aae
        a25ab213  48a6b46c  1b9d9bcb  092c5be6
        546ca624  1bec45d5  87f47473  96f0992e
} { expr 0x$x }] "block function - additional test vector 4"

set key [string repeat \x00 32]
set nonce [string repeat \x00 11]\x02
assertEqual [chacha20::block [chacha20::initialState $key 0 $nonce] 0] [lmap x {
        374dc6c2  3736d58c  b904e24a  cd3f93ef
        88228b1a  96a4dfb3  5b76ab72  c727ee54
        0e0e978a  f3145c95  1b748ea8  f786c297
        99c28f5f  628314e8  398a19fa  6ded1b53
} { expr 0x$x }] "block function - additional test vector 5"

set key [string repeat \x00 32]
set nonce [string repeat \x00 12]
set plaintext [string repeat \x00 64]
assertEqual [chacha20 encrypt $key $plaintext -nonce $nonce] [fromHex {
  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
  da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
  6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
}] "encryption - additional test vector 1"

set key [string repeat \x00 31]\x01
set nonce [string repeat \x00 11]\x02
set plaintext [string trim [regsub -all {\s+} {
    Any submission to the IETF intended by the Contributor for publication
    as all or part of an IETF Internet-Draft or RFC and any statement made
    within the context of an IETF activity is considered an "IETF Contribution".
    Such statements include oral statements in IETF sessions, as well as
    written and electronic communications made at any time or place, which are
    addressed to} { }]]
assertEqual [chacha20 encrypt $key $plaintext -nonce $nonce -counter 1] [fromHex {
  a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
  41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
  2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
  0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
  40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
  20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
  42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
  68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
  d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
  42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
  c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
  e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
  08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
  a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
  cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
  a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
  c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
  8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
  58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
  be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
  98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
  14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
  7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
  c4 fd 80 6c 22 f2 21                  
}] "encryption - additional test vector 2"

set key [fromHex {1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
                  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0}]
set nonce [string repeat \x00 11]\x02
set plaintext [fromHex {
  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61 
  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e  
}]

assertEqual [chacha20 encrypt $key $plaintext -nonce $nonce -counter 42] [fromHex {
  62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df 
  5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf
  16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71
  fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb
  f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6
  1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77
  04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1
  87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
}] "encryption - additional test vector 3"

# Hchacha20 core - libsodium test vectors

foreach {key input expected} {
    24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc d9660c5900ae19ddad28d6e06e45fe5e 5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3
    80a5f6272031e18bb9bcd84f3385da65e7731b7039f13f5e3d475364cd4d42f7 c0eccc384b44c88e92c57eb2d5ca4dfa 6ed11741f724009a640a44fce7320954c46e18e0d7ae063bdbc8d7cf372709df 
    cb1fc686c0eec11a89438b6f4013bf110e7171dace3297f3a657a309b3199629 fcd49b93e5f8f299227e64d40dc864a3 84b7e96937a1a0a406bb7162eeaad34308d49de60fd2f7ec9dc6a79cbab2ca34 
    6640f4d80af5496ca1bc2cfff1fefbe99638dbceaabd7d0ade118999d45f053d 31f59ceeeafdbfe8cae7914caeba90d6 9af4697d2f5574a44834a2c2ae1a0505af9f5d869dbe381a994a18eb374c36a0 
    0693ff36d971225a44ac92c092c60b399e672e4cc5aafd5e31426f123787ac27 3a6293da061da405db45be1731d5fc4d f87b38609142c01095bfc425573bb3c698f9ae866b7e4216840b9c4caf3b0865 
    809539bd2639a23bf83578700f055f313561c7785a4a19fc9114086915eee551 780c65d6a3318e479c02141d3f0b3918 902ea8ce4680c09395ce71874d242f84274243a156938aaa2dd37ac5be382b42 
    1a170ddf25a4fd69b648926e6d794e73408805835c64b2c70efddd8cd1c56ce0 05dbee10de87eb0c5acb2b66ebbe67d3 a4e20b634c77d7db908d387b48ec2b370059db916e8ea7716dc07238532d5981 
    3b354e4bb69b5b4a1126f509e84cad49f18c9f5f29f0be0c821316a6986e15a6 d8a89af02f4b8b2901d8321796388b6c 9816cb1a5b61993735a4b161b51ed2265b696e7ded5309c229a5a99f53534fbc 
    4b9a818892e15a530db50dd2832e95ee192e5ed6afffb408bd624a0c4e12a081 a9079c551de70501be0286d1bc78b045 ebc5224cf41ea97473683b6c2f38a084bf6e1feaaeff62676db59d5b719d999b 
    c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7 31f0204e10cf4f2035f9e62bb5ba7303 0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c 
} {
    assertEqual $expected [binary encode hex [hchacha20 core [binary decode hex $key] [binary decode hex $input]]] "hchacha20 core"
}

# XChaCha20 - libsodium test vectors

foreach {key nonce expected} {
    79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4 b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419 c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c 
    ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173 a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4 2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d 
    3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682 56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0 
    5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4 a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771 8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0 
    eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf01060b4e a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64 23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae140447575f2916c5d71108e3b13357eaf86f060cb 
    91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d3dbaab2 410e854b2a911f174aaf1a56540fc3855851f41c65967a4e cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479faef6 
    6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c422842b6 6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5 8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f1546be662e54feb1203e2 
    d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd20c2b391 fd37da2db31e0c738754463edadc7dafb0833bd45da497fc 47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb868be3d486f6516606d85e5643becc473b370871ab9ef8e2a728f73b92bd98e6e26ea7c8ff96ec5a9e8de95e1eee9300c 
    aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611eb4dcf3 6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63 a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b3544d13151e67513b8aaa1ac5af2d7fd0d5e4216964324838 
    9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232 c047548266b7c370d33566a2425cbf30d82d1eaf5294109e a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc 
} {
    set plaintext [binary decode hex [string repeat 0 [string length $expected]]]
    assertEqual $expected [binary encode hex [xchacha20 encrypt [binary decode hex $key] $plaintext -nonce [binary decode hex $nonce]]] "xchacha20"
}
# vim: ft=tcl