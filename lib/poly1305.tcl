# poly1305.tcl --
# 
#       Implementation of the Poly1305 authenticator. 
#
# Copyright (c) 2018 Neil Madden.
# License: Tcl-style

package require Tcl         8.6
package provide poly1305    1.0.0

# poly1305 compute key message
# poly1305 verify key message tag
#
#       Computes or verifies a Poly-1305 message authentication code (MAC).
#       Poly1305 is a fast, cryptographically secure polynomial MAC. It is
#       information theoretically secure, although only if the key is only used
#       to authenticate a single message. The key can be recovered if more than
#       one message tag is computed with the same key. Therefore either a per-message
#       fresh key should be computed, or else the tag should be encrypted under
#       a separate key.
#
namespace eval ::poly1305 {
    namespace export compute verify
    namespace ensemble create

    #proc debug {msg args} { puts [format $msg {*}$args] }
    proc debug args {}
    
    proc clamp r {
        list [expr {[lindex $r 0] & 0x3ffffff}] \
             [expr {[lindex $r 1] & 0x3ffff03}] \
             [expr {[lindex $r 2] & 0x3ffc0ff}] \
             [expr {[lindex $r 3] & 0x3f03fff}] \
             [expr {[lindex $r 4] & 0x00fffff}]
    }
    
    proc verify {key data tag} {
        set expected [compute $key $data]
        equals $expected $tag
    }
    
    # constant time equality check
    proc equals {a b} {
        if {[string length $a] != [string length $b]} {
            return 0
        }
        set ret 0
        binary scan $a c* as
        binary scan $b c* bs
        foreach x $as y $bs {
            set ret [expr {$ret | ($x ^ $y)}]
        }
        expr {$ret == 0}
    }

    # Loads a 130-bit little-endian number and represents it as 5 26-bit limbs.
    # This internal format allows to delay carry propagation, resulting in a fast
    # and constant-time representation.
    proc load_130_le_26 bin {
        # Scan as 5 32-bit little-endian integers, rewinding (X) by one byte between each.
        # We then mask each down to a 26-bit integer.
        if {[binary scan $bin iuXiuXiuXiuXiu x0 x1 x2 x3 x4] != 5} {
            error "unable to parse data: [binary encode hex $bin]"
        }
        set x0 [expr {$x0           & 0x03ffffff}]
        set x1 [expr {($x1 >> 2)    & 0x03ffffff}]
        set x2 [expr {($x2 >> 4)    & 0x03ffffff}]
        set x3 [expr {($x3 >> 6)    & 0x03ffffff}]
        set x4 [expr {($x4 >> 8)    & 0x03ffffff}]

        list $x0 $x1 $x2 $x3 $x4
    }

    proc carry limb { 
        list [expr {$limb & 0x03FFFFFF}] [expr {$limb >> 26}] 
    }

    namespace eval tcl { namespace eval mathfunc {} }
    proc tcl::mathfunc::mul64 {x y} {
        expr {wide(wide($x) * wide($y))}
    }

    proc compute {key data} {
        variable INT32
        if {[string length $key] != 32} {
            error "key must be exactly 32 bytes"
        }
        set r [clamp [load_130_le_26 $key]]
        lassign $r r0 r1 r2 r3 r4

        binary scan $key iu4iu4 -> s

        set s1 [expr {$r1 * 5}]
        set s2 [expr {$r2 * 5}]
        set s3 [expr {$r3 * 5}]
        set s4 [expr {$r4 * 5}]

        lassign {0 0 0 0 0} a0 a1 a2 a3 a4

        set len [string length $data]
        for {set i 0} {$i < $len} {incr i 16} {
            set end [expr {min($i + 15, $len-1)}]

            set bytes [string range $data $i $end]\x01[string repeat \x00 [expr {15 - ($end - $i)}]]

            debug "block = %s" [binary encode hex [string reverse $bytes]]

            binary scan [string index $bytes 16] c c
            lassign [load_130_le_26 $bytes] n0 n1 n2 n3 n4

            incr a0 $n0
            incr a1 $n1
            incr a2 $n2
            incr a3 $n3
            incr a4 [expr {$n4 | ($c << 24)}]

            debug "a = %08x %08x %08x %08x %08x" $a0 $a1 $a2 $a3 $a4

            set d0 [expr {mul64($a0,$r0) + mul64($a1,$s4) + mul64($a2,$s3) + mul64($a3,$s2) + mul64($a4,$s1)}]
            set d1 [expr {mul64($a0,$r1) + mul64($a1,$r0) + mul64($a2,$s4) + mul64($a3,$s3) + mul64($a4,$s2)}]
            set d2 [expr {mul64($a0,$r2) + mul64($a1,$r1) + mul64($a2,$r0) + mul64($a3,$s4) + mul64($a4,$s3)}]
            set d3 [expr {mul64($a0,$r3) + mul64($a1,$r2) + mul64($a2,$r1) + mul64($a3,$r0) + mul64($a4,$s4)}]
            set d4 [expr {mul64($a0,$r4) + mul64($a1,$r3) + mul64($a2,$r2) + mul64($a3,$r1) + mul64($a4,$r0)}]

            debug "d = %08x %08x %08x %08x %08x" $d0 $d1 $d2 $d3 $d4

            # Reduce mod 2^130-5 (partially)
            lassign [carry $d0] a0 c
            incr d1 $c
            lassign [carry $d1] a1 c
            incr d2 $c
            lassign [carry $d2] a2 c
            incr d3 $c
            lassign [carry $d3] a3 c
            incr d4 $c
            lassign [carry $d4] a4 c
            incr a0 [expr {$c * 5}]
            lassign [carry $a0] a0 c
            incr a1 $c

            debug "a = %08x %08x %08x %08x %08x" $a0 $a1 $a2 $a3 $a4
        }

        # Final reduction mod 2^130-5
        lassign [carry $a1] a1 c
        incr a2 $c
        lassign [carry $a2] a2 c
        incr a3 $c
        lassign [carry $a3] a3 c
        incr a4 $c
        lassign [carry $a4] a4 c
        incr a0 [expr {$c * 5}]
        lassign [carry $a0] a0 c
        incr a1 $c

        debug "a = %08x %08x %08x %08x %08x" $a0 $a1 $a2 $a3 $a4

        # a-p
        set g0 [expr {$a0 + 5}]
        lassign [carry $g0] g0 c
        set g1 [expr {$a1 + $c}]
        lassign [carry $g1] g1 c
        set g2 [expr {$a2 + $c}]
        lassign [carry $g2] g2 c
        set g3 [expr {$a3 + $c}]
        lassign [carry $g3] g3 c
        set g4 [expr {$a4 + $c - (1 << 26)}]

        debug "g = %08x %08x %08x %08x %08x" $g0 $g1 $g2 $g3 $g4

        # Use bit-slicing to select a if a < p or a - p if a >= p
        set mask [expr {$g4 >> 63}]
        set a0 [expr {$a0 & $mask}]
        set a1 [expr {$a1 & $mask}]
        set a2 [expr {$a2 & $mask}]
        set a3 [expr {$a3 & $mask}]
        set a4 [expr {$a4 & $mask}]

        # a = a mod 2^128
        set a0 [expr {($a0         | ($a1 << 26)) & 0xFFFFFFFF}]
        set a1 [expr {(($a1 >> 6)  | ($a2 << 20)) & 0xFFFFFFFF}]
        set a2 [expr {(($a2 >> 12) | ($a3 << 14)) & 0xFFFFFFFF}]
        set a3 [expr {(($a3 >> 18) | ($a4 << 8 )) & 0xFFFFFFFF}]

        # mac = (a + s) mod 2^128
        set c [expr {$a0 + [lindex $s 0]}]
        set a0 [expr {$c & 0xFFFFFFFF}]
        set c [expr {$a1 + [lindex $s 1] + ($c >> 32)}]
        set a1 [expr {$c & 0xFFFFFFFF}]
        set c [expr {$a2 + [lindex $s 2] + ($c >> 32)}]
        set a2 [expr {$c & 0xFFFFFFFF}]
        set c [expr {$a3 + [lindex $s 3] + ($c >> 32)}]
        set a3 [expr {$c & 0xFFFFFFFF}]

        binary format iiii $a0 $a1 $a2 $a3
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

set key [fromHex {85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:0
      3:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b}]
set msg "Cryptographic Forum Research Group"

set tag [fromHex {a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9}]

assertEqual [poly1305 compute $key $msg] $tag "poly1305 compute"
assertEqual 1 [poly1305 verify $key $msg $tag] "poly1305 verify"
assertEqual 0 [poly1305 verify $key $msg [string range $tag 1 end]] "poly1305 verify - wrong length"
assertEqual 0 [poly1305 verify $key $msg [string reverse $tag]] "poly1305 verify - wrong tag"

# vim: ft=tcl