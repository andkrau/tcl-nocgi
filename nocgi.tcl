package require Thread
encoding system utf-8

if { $argc > 0 } {
    set i 0
    foreach arg $argv {
        set arg [string trimleft $arg -]
        incr i
        set $arg [lindex $argv $i]
    }
} else {
    puts "no command line arguments passed!"
    exit
}
if { ![info exists config]} {
    puts "Missing arguments!"
    exit
}

set config [open $config r]
set config [read -nonewline $config]

## Tuning parameters.
variable tuning $config
cd [dict get $tuning site_root]
rename cd ""

## Put anything httpd into an own namespace.
namespace eval ::httpd:: {

    set worker_script {
        package require ncgi
        package require sha256
        package require aes
        
        namespace eval ::httpd:: {
            variable startTag [dict get $tuning start_tag]
            variable endTag [dict get $tuning end_tag]
            variable root [dict get $tuning site_root]            
            variable cipherKey [dict get $tuning cipher_key]
            variable hmacKey [dict get $tuning hmac_key]
            variable request [dict create]
            variable response [dict create]
            interp alias {} echo {} append html

            ## Handle timeout.
            proc timeout {sock} {
                ## Close the channel.
                catch {chan close $sock}
                tsv::lappend tsv freeThreads [thread::id]
                thread::cond notify [tsv::get tsv cond]
            }
            
            proc embed {incFile} {
                set incFile [string trimleft $incFile /]
                return [parse inline $incFile]
            }
            
            proc include {incFile} {
                set incFile [string trimleft $incFile /]
                return [parse main $incFile]
            }

            proc insert {incFile} {
                set incFile [string trimleft $incFile /]
                if {[catch {set chan [open $incFile r]}]} {
                    set pageText "<BR><BOLD>File $incFile not found!</BOLD><BR>"
                } else {
                    set pageText [encoding convertto utf-8 [read $chan]]
                    close $chan
                }
                return $pageText
            }

            proc setResponse {parent data args} {
                if {$args eq ""} {
                    dict set httpd::response $parent $data
                } else {
                    dict set httpd::response $parent $data $args
                }
            }

            proc setRequest {parent data args} {
                if {$args eq ""} {
                    dict set httpd::request $parent $data
                } else {
                    dict set httpd::request $parent $data $args
                }
            }
            
            proc getResponse {parent args} {
                if {$args eq ""} {
                    return [dict get $httpd::response $parent]
                } else {
                    return [dict get $httpd::response $parent $args]
                }
            }
            
            proc getRequest {parent args} {
                if {$args eq ""} {
                    return [dict get $httpd::request $parent]
                } else {
                    return [dict get $httpd::request $parent $args]
                }
            }

            proc existResponse {parent args} {
                if {$args eq ""} {
                    return [dict exist $httpd::response $parent]
                } else {
                    return [dict exist $httpd::response $parent $args]
                }
            }

            proc existRequest {parent args} {
                if {$args eq ""} {
                    return [dict exist $httpd::request $parent]
                } else {
                    return [dict exist $httpd::request $parent $args]
                }
            }

            #The following evaluates the THP script.
            proc parse {type incFile} {
                variable startTag
                variable endTag
                set cookie ""
                set tclStr {}
                set html ""
                set stLen [string length $startTag]
                set etLen [string length $endTag]
                catch {unset tclStr}
                # Open and read the include file, this may be the referring script.
                # !!!  Must add in checks for recursion or a recursion limit!!!
                if {[catch {set chan [open $incFile r]}]} {
                    #append tclStr "append html \"<BR><BOLD>File $incFile not found!</BOLD><BR>\"\n"
                    set pageText "<BR><BOLD>File $incFile not found!</BOLD><BR>"
                } else {
                    set pageText [encoding convertto utf-8 [read $chan]]
                    close $chan
                }
                regexp {(^|\n)\s*(<.*$)} $pageText {} {} pageText
                set pageTextLen [string length $pageText]

                set endPos 0
                #puts stderr "pageTextLen=$pageTextLen"
                while { $endPos != -1 && ($endPos < [expr $pageTextLen - 1]) && ( [set startPos [string first $startTag $pageText $endPos]] != -1 || [set startPos $pageTextLen] > 0)} {
                    
                    set subText [string range $pageText $endPos [expr $startPos-1] ]
                    #puts stderr "subText($incFile), $startPos, $endPos=:$subText:"
                    if {$subText != {}} {
                        append tclStr "append html [list [ string map {"    " "" "\t" "" "\r" ""} [string trim [string range $pageText $endPos [expr $startPos-1]] \n] ]]\n"
                    }
                    set endPos [string first $endTag $pageText $startPos]
                    set subText [string range $pageText [expr $startPos+$stLen] [expr $endPos-1] ]
                    #puts stderr "subText2($incFile), $startPos, $endPos=:$subText:"
                    if {$endPos != -1 && $subText != {}} {
                        set subText [string trim $subText]
                        if {[string first "=" $subText] == 0} {
                            set subText [string range $subText 1 [string length $subText]]
                            append tclStr "append html [expr {$subText}]\n"
                        } elseif {[string first "+" $subText] == 0} {
                            set subText [string range $subText 1 [string length $subText]]
                            append tclStr "append html [list [parse inline $incFile]]\n"
                        } elseif {[string first "!" $subText] == 0} {
                            set subText [string range $subText 1 [string length $subText]]
                            append tclStr "append html \[$subText\]\n"
                        } else {
                            append tclStr "$subText\n"
                            #puts "! $subText !"
                        }
                    }
                    if {$endPos > 0} {
                        incr endPos $etLen
                    }
                }

                # Do not eval tclStr here if its the main script,
                # header checking must be done first.
                if {$type == "inline"} {
                    eval $tclStr
                    return $html
                }
                return $tclStr
            }
            
            proc decryptSession {encrypted} {
                variable hmacKey
                variable cipherKey
                set hmac [string range $encrypted 0 63]
                set crypto [string range $encrypted 64 end]
                if {$hmac == [::sha2::hmac -hex $hmacKey $crypto]} {
                    set decrypted [::aes::aes -hex -mode ecb -dir decrypt -key [binary format H* $cipherKey] [binary format H* $crypto]]
                    set decrypted [binary decode hex $decrypted]
                    return $decrypted
                } else {
                    return "error:DecryptionFailed"
                }
            }

            proc encryptSession {decrypted} {
                variable hmacKey
                variable cipherKey
                set crypto [::aes::aes -hex -mode ecb -dir encrypt -key [binary format H* $cipherKey] $decrypted]
                set hmac [::sha2::hmac -hex $hmacKey $crypto]
                set encrypted "${hmac}${crypto}"
                return $encrypted
            }
            
            ## Process a single HTTP request.
            proc process {url} {
                variable request
                variable response
                variable root
                set html {}
                set url [string trimright $url /]
                set lastFolder [lindex [split $url /] end]
                
                # If it exists, set the index file. Otherwise, throw an error.
                if {[file exists ${root}${url}/index.thp]} {
                    set thpFile "${root}${url}/index.thp"
                } elseif {[file exists ${root}${url}/${lastFolder}.thp]} {
                    set thpFile "${root}${url}/${lastFolder}.thp"
                } else {
                    setResponse code 404
                    setResponse body "404 File Not Found"
                    setResponse type "text/html; charset=[encoding system]"
                    setResponse connection "keep-alive"
                    setResponse headers {}
                    return
                }

                # Interpret the THP script and convert to pure tcl.
                set tclStr [parse main $thpFile]
                #puts $tclStr
                # Execute the tcl script (with embedded HTML) inside this interp
                if { [catch {eval $tclStr} fid] } {
                    puts stderr "Error evaluating THP:"
                    puts stderr "$::errorInfo"
                    setResponse code 500
                    setResponse body "500 Internal Server Error - $fid"
                    setResponse type "text/html; charset=[encoding system]"
                    setResponse connection "close"
                    setResponse headers {}
                } else {
                    setResponse code 200
                    setResponse body $html
                    if {![existResponse type]} {
                        setResponse type "text/html; charset=[encoding system]"
                    }
                    setResponse connection "keep-alive"
                    setResponse headers {}
                }
                # Returns the completed HTML
                return
            }
            
            ## Accept incoming connection
            try {      
                ## Do blocking I/O on client socket. This actually improves CPU usage while not impacting performance at all.
                chan configure $sock -blocking 1
                set served 0
                while {1} {
                    ## HTTP headers are ascii encoded with CRLF line ends, line buffering is fine.
                    chan configure $sock -encoding ascii -translation crlf -buffering line
                    ## Read the request line.
                    set requestline {}
                    while {$requestline eq {}} {
                        ## Get request line.
                        chan gets $sock requestline 
                        
                        ## Stop processing if client has closed the channel. 
                        if {[chan eof $sock]} {
                            break
                        }
                    }
                   
                    if {$requestline eq {}} {
                        break
                    }

                    ## Default header values.
                    set headers {}
                    dict set headers Accept-Encoding "identity;q=0.001"
                    
                    ## Read additional header lines.
                    for {set i 0} {$i < [dict get $::tuning header_lines_max]} {incr i} {
                        ## Read header line.
                        chan gets $sock headerline
                        ## It's an error to have an eof before header end (empty line). 
                        if {[chan eof $sock]} { throw {HTTPD REQUEST_HEADER CONNECTION_CLOSED} "connection closed by client during read of HTTP request header"}

                        ## Break loop on last header line.
                        if {$headerline eq {}} break

                        ## This is a regular header line.
                        ## Remember field name and value. Repeated field values are lappended.
                        #! Would using ::ncgi::parseMimeValue be a better way to cope with headers?
                        set sep [string first ":" $headerline]
                        dict lappend headers [string range $headerline 0 $sep-1] [string trim [string range $headerline $sep+1 end]]
                    }
                    
                    ## Join appended header fields with comma,space (RFC2616, section 4.2).
                    dict for {name values} $headers {
                            dict set headers $name [join $values ", "]
                    }

                    ## Get HTTP method, protocol version, URL and, if available, query.
                    lassign $requestline method url version
                    if {[string first "?" $url] != -1} {
                        set url [split $url ?]
                        lassign $url url query
                    } else {
                        set query ""
                    }

                    if {$method == "POST" && [chan pending input $sock] > 0} {
                        if { [dict get $headers Content-Type] == "application/x-www-form-urlencoded"} {
                            set body [chan read $sock [chan pending input $sock]]
                            ::ncgi::input $body
                            ::ncgi::parse
                            dict set httpd::request body [::ncgi::nvlist]
                        } else {
                            puts "invalid POST of type [dict get $headers Content-Type] received, ignoring."
                        }
                    }

                    if {$method == "GET" && [string length $query] > 0} {
                        ::ncgi::input $query
                        ::ncgi::parse
                        dict set httpd::request query [::ncgi::nvlist]
                    }

                    if {[dict exists $headers Cookie]} {
                        set cookie [dict get $headers Cookie]
                        set cookie [string map {"; " "&"} $cookie]
                        ::ncgi::input $cookie
                        ::ncgi::parse
                        if {[dict exist [::ncgi::nvlist] SESSION_ID]} {
                            dict set httpd::request cookie [decryptSession [dict get [::ncgi::nvlist] SESSION_ID]]
                        }
                    }

                    ## Get the finished result.
                    process $url

                    incr served
                    if {$served > 100} {
                        setResponse connection "close"
                    }
                    ## Send result header.
                    chan configure $sock -encoding ascii -translation crlf -buffering full
                    #puts $sock [::ncgi::header [getResponse type] Content-Length [string length [getResponse body]] Connection [getResponse connection]]
                    puts $sock "$version [getResponse code]"
                    puts $sock "Content-Type: [getResponse type]"
                    puts $sock "Content-Length: [string length [getResponse body]]"
                    puts $sock "Connection: [getResponse connection]"
                    if {[existResponse cookie]} {
                        puts $sock "Set-Cookie: SESSION_ID=[encryptSession [getResponse cookie]]; Secure; HttpOnly; SameSite=Strict"
                    }
                    puts $sock ""
                    ## Send result.
                    chan configure $sock -encoding binary -translation binary -buffering full
                    puts -nonewline $sock [getResponse body]
                    set response {}
                    set request {}
                    chan flush $sock
                    if {$served > 100} {
                        puts "Served $served requests, retiring thread"
                        break
                    }
                }
            }        trap {HTTPD REQUEST_HEADER TOO_MANY_LINES} {} {
                    puts stderr "HTTPD REQUEST_HEADER TOO_MANY_LINES $addr"
            }        trap {HTTPD REQUEST_HEADER CONNECTION_CLOSED} {} {
                    puts stderr "HTTPD REQUEST_HEADER CONNECTION_CLOSED $addr"
            }        trap {HTTPD REQUEST_METHOD UNSUPPORTED} {} {
                    puts stderr "HTTPD REQUEST_METHOD UNSUPPORTED $addr"
            } trap {POSIX ECONNABORTED} {} {
                    puts stderr "SSL ERROR $addr"
            }        on error {} {
                    puts stderr "$::errorCode $::errorInfo"
            }        finally {
                    ::httpd::timeout $sock
            }            
        }
    }

    ##
    # Handle a new connection.
    proc handle_connect {sock addr port} {
        chan configure $sock -blocking 0 -encoding ascii -translation crlf -buffering line
        chan event $sock r [namespace code [list handle_request $sock $addr $port]]
    }
    
    ##
    # Handle a request on a different thread.
    proc handle_request {sock addr port} {
        variable worker_script
        variable tuning
        
        # We can't read from the socket once we begin serving the request, and
        # we don't need a timeout anymore.
        chan event $sock r {}

        # Get a free thread. This call might wait if max_threads was reached.
        set tid [get_thread]
        
        # Set up and invoke the worker thread by transferring the client socket
        # to the thread and setting up the necessary state data.
        thread::transfer $tid $sock
        thread::send $tid [list set sock  $sock]
        thread::send $tid [list set addr  $addr]
        thread::send $tid [list set port  $port]
        thread::send $tid [list set tuning  $::tuning]
        thread::send -async $tid $worker_script

        # Cleanup this connection's state in the master thread. The worker
        # thread is going to handle it from now on.
        cleanup $sock
    }

    ##
    # Get a free thread by creating up to max_threads. If none is available,
    # wait until one is fed back to the free threads list.
    proc get_thread {} {
        variable max_threads
        variable nofThreads

        # create a new thread
        if {$nofThreads < $max_threads} {
            set tid [thread::create]
            thread::preserve $tid
            puts "There are [tsv::llength tsv freeThreads] free threads"
            incr nofThreads
            puts "There are [expr {$nofThreads -  [tsv::llength tsv freeThreads]}] active threads"
            puts "There are $nofThreads total threads"
            return $tid
        }
        puts "There are $nofThreads total threads"
        puts "There are [expr {$nofThreads -  [tsv::llength tsv freeThreads]}] active threads"
        puts "There are [tsv::llength tsv freeThreads] free threads"
        # if there's no free threads, wait
        thread::mutex lock [tsv::get tsv mutex]
        while {[tsv::llength tsv freeThreads] == 0} {
            thread::cond wait [tsv::get tsv cond] [tsv::get tsv mutex]
        }
        thread::mutex unlock [tsv::get tsv mutex]
        tsv::lock tsv {
            set tid [tsv::lindex tsv freeThreads end]
            tsv::lpop tsv freeThreads end
        }
        return $tid
    }
    
    variable max_threads [dict get $tuning max_threads]
    ##
    # Thread pool -related variables. We don't use tpool because we don't have
    # a way to pass channels when posting a job into a tpool instance.
    variable nofThreads  0
    tsv::set tsv freeThreads [list]
    tsv::set tsv mutex [thread::mutex create]
    tsv::set tsv cond [thread::cond create]
    
    ##
    # Cleanup a connection's data.
    proc cleanup {sock} {
        catch {chan close $sock}
    }
}
    set sk [socket -server ::httpd::handle_connect [dict get $tuning listen_port]]
    vwait forever