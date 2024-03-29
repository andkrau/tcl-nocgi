package require Thread
package require inifile
encoding system utf-8

if {$argc > 0} {
    set configFile [lindex $argv 0]
} else {
    puts "No configuration file specified!"
    exit
}

if {![file isfile $configFile]} {
    puts "Configuration file does not exist!"
    exit
}

set config [::ini::open $configFile]
variable nocgi_config [::ini::get $config nocgi]
variable site_config [::ini::get $config site]
::ini::close $config

## Tuning parameters
set root [string trimright [dict get $nocgi_config site_root] /]
dict set nocgi_config site_root $root
set scriptDir [file dirname [file normalize [info script]]]
dict append nocgi_config "lib_path" "${scriptDir}/lib"
pkg_mkIndex "${scriptDir}/lib"
if {[file isdirectory ${root}/lib]} {
    dict append nocgi_config "lib_path" "${root}/lib"
    pkg_mkIndex "${root}/lib"
}
cd $root
rename cd ""

##
# The following script is used by worker threads to handle client
# connections. The worker thread is responsible for communicating with the
# client over the client socket and for closing the connection once done.
set worker_script {
    namespace eval ::httpd:: {
        variable configFile $_configFile
        variable nocgi_config $_nocgi_config
        variable site_config $_site_config
        lappend auto_path [dict get $nocgi_config lib_path]
        package require ncgi
        package require json
        package require chacha20poly1305
        variable startTag [dict get $nocgi_config start_tag]
        variable endTag [dict get $nocgi_config end_tag]
        variable root [dict get $nocgi_config site_root]
        variable cryptoKey [dict get $nocgi_config crypto_key]
        variable request [dict create]
        variable response [dict create]
        interp alias {} echo {} append html

        proc ::json::dict2json {dict} {
            ::json::write object {*}[dict map {key value} $dict {
                set value [::json::write string $value]
            }]
        }

        proc include {incFile} {
            set incFile [string trimleft $incFile /]
            upvar 1 childFile childFile
            set childFile $incFile
            uplevel 1 {eval [parse $childFile]}
        }

        proc readfile {incFile} {
            set incFile [string trimleft $incFile /]
            if {[catch {set chan [open $incFile r]}]} {
                set pageText "<BR><BOLD>File $incFile not found!</BOLD><BR>"
            } else {
                set pageText [encoding convertto utf-8 [read $chan]]
                close $chan
            }
            upvar 1 fileread fileread
            set fileread $pageText
            uplevel 1 {echo $fileread}
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
                return [dict exists $httpd::response $parent]
            } else {
                return [dict exists $httpd::response $parent $args]
            }
        }

        proc existRequest {parent args} {
            if {$args eq ""} {
                return [dict exists $httpd::request $parent]
            } else {
                return [dict exists $httpd::request $parent $args]
            }
        }

        #The following evaluates the THP script.
        proc parse {incFile} {
            variable startTag
            variable endTag
            set stLen [string length $startTag]
            set etLen [string length $endTag]
            # Open and read the include file.
            if {[catch {set chan [open $incFile r]}]} {
                set pageText "<BR><BOLD>File $incFile not found!</BOLD><BR>"
            } else {
                set pageText [encoding convertto utf-8 [read $chan]]
                close $chan
            }

            set pageTextLen [string length $pageText]
            set endPos 0

            while { $endPos != -1 && ($endPos < [expr $pageTextLen - 1]) && ( [set startPos [string first $startTag $pageText $endPos]] != -1 || [set startPos $pageTextLen] > 0)} {

                set subText [string range $pageText $endPos [expr $startPos-1]]
                if {$subText != {}} {
                    append tclStr "echo [list [string range $pageText $endPos [expr $startPos-1] ]]\n"
                }
                set endPos [string first $endTag $pageText $startPos]
                set subText [string range $pageText [expr $startPos+$stLen] [expr $endPos-1]]
                if {$endPos != -1 && $subText != {}} {
                    set subText [string trim $subText]
                    if {[string first "=" $subText] == 0} {
                        set subText [string range $subText 1 [string length $subText]]
                        append tclStr "echo [expr {$subText}]\n"
                    } elseif {[string first "+" $subText] == 0} {
                        set subText [string range $subText 1 [string length $subText]]
                        append tclStr "include $subText\n"
                    } elseif {[string first "!" $subText] == 0} {
                        set subText [string range $subText 1 [string length $subText]]
                        append tclStr "echo \[$subText\]\n"
                    } else {
                        append tclStr "$subText\n"
                    }
                }
                if {$endPos > 0} {
                    incr endPos $etLen
                }
            }
            return $tclStr
        }

        proc decryptSession {encrypted} {
            variable cryptoKey
            binary scan [binary decode base64 [string map {- + _ /} $encrypted]] H* encrypted
            set time [string range $encrypted 0 7]
            set nonce [string range $encrypted 8 31]
            set crypto [string range $encrypted 32 end]
            scan $time %x stamp
            set now [clock seconds]
            if {$now - $stamp < 3600} {
                puts [expr $now - $stamp]
                try {
                    set decrypted [::chacha20poly1305::decrypt [binary format H* $cryptoKey] [binary format H* $crypto] -assocdata [binary format H* $time] -nonce [binary format H* $nonce]]
                    return $decrypted
                } on error {} {
                    return "error:DecryptionFailed"
                }
            } else {
                return "error:CookieTimeout"
            }
        }

        proc encryptSession {decrypted} {
            variable cryptoKey
            set id [string range [thread::id] end-3 end]
            set count [string range [format %06llx [info cmdcount]] end-5 end]
            set ms [string range [format %014llx [clock microseconds]] end-13 end]
            set time [string range [format %08llx [clock seconds]] end-7 end]
            set nonce "${id}${count}${ms}"
            binary scan [::chacha20poly1305::encrypt [binary format H* $cryptoKey] $decrypted -assocdata [binary format H* $time] -nonce [binary format H* $nonce]] H* encrypted
            return [string map {+ - / _ = {}} [binary encode base64 [binary format H* ${time}${nonce}${encrypted}]]
        }

        ## Process a single HTTP request.
        proc process {url root} {
            set html {}
            set url [string trimright $url /]
            set lastFolder [lindex [split $url /] end]

            # If it exists, set the index file. Otherwise, throw an error.
            if {[file exists ${root}/${url}/index.thp]} {
                set thpFile "${root}/${url}/index.thp"
            } elseif {[file exists ${root}/${url}/${lastFolder}.thp]} {
                set thpFile "${root}/${url}/${lastFolder}.thp"
            } elseif {[file exists ${root}/public${url}]} {
                set fp [open ${root}/public${url} r]
                fconfigure $fp -translation binary
                set inBinData [read $fp]
                close $fp
                setResponse code 200
                setResponse body $inBinData
                setResponse type ""
                setResponse connection "keep-alive"
                setResponse headers {}
                return
            } else {
                setResponse code 404
                setResponse body "404 File Not Found"
                setResponse type "text/html; charset=[encoding system]"
                setResponse connection "keep-alive"
                setResponse headers {}
                return
            }

            # Interpret the THP script and convert to pure tcl.
            set tclStr [parse $thpFile]
            #puts $tclStr

            # Unset all variables other than tclStr & html
            unset url
            unset lastFolder
            unset thpFile
            unset root

            # Execute the tcl script (with embedded HTML) inside this interp
            if { [catch $tclStr] } {
                set time [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
                puts stderr "\n$time Error evaluating THP:"
                puts stderr "$::errorInfo"
                setResponse code 500
                setResponse body "500 Internal Server Error - $time $::errorCode"
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

        ## Accept an incoming connection
        proc accept {sock nocgi_config site_config} {
            thread::attach $sock
            variable startTag
            variable endTag
            variable root
            variable cryptoKey
            variable request
            variable response

            try {
                ## Do blocking I/O on client socket. This actually improves CPU usage while not impacting performance at all.
                chan configure $sock -blocking 1
                set served 0
                while {1} {
                    if {[string length $request] > 0} {
                        puts $request
                    }
                    if {[string length $response] > 0} {
                        puts $response
                    }
                    ## HTTP headers are ascii encoded with CRLF line endings, line buffering is fine.
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
                    while {1} {
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
                    process $url $root

                    incr served
                    if {$served > 100} {
                        setResponse connection "close"
                    }
                    ## Send result header.
                    chan configure $sock -encoding ascii -translation crlf -buffering full
                    #puts $sock [::ncgi::header [getResponse type] Content-Length [string length [getResponse body]] Connection [getResponse connection]]
                    puts $sock "HTTP/1.0 [getResponse code]"
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
            } trap {HTTPD REQUEST_HEADER CONNECTION_CLOSED} {} {
                puts stderr "HTTPD REQUEST_HEADER CONNECTION_CLOSED $addr"
            } trap {HTTPD REQUEST_METHOD UNSUPPORTED} {} {
                puts stderr "HTTPD REQUEST_METHOD UNSUPPORTED $addr"
            } trap {POSIX ECONNABORTED} {} {
                puts stderr "CONNECTION ABORTED $addr"
            } on error {} {
                puts stderr "$::errorCode $::errorInfo"
            } finally {
                ## Close the channel.
                catch {chan close $sock}
            }
        }
    }
}

## Variables to be substituted and available to the pool's initcmd
set init_helper {
        set _configFile [list $configFile]
        set _nocgi_config [list $nocgi_config]
        set _site_config [list $site_config]
}

## Handle a new connection
proc connect {sock addr port} {
    chan configure $sock -blocking 0 -encoding ascii -translation crlf -buffering line
    chan event $sock r [list transfer $sock $addr $port]
}

## Transfer a request to another thread
proc transfer {sock addr port} {
    variable pool
    variable nocgi_config
    variable site_config
    thread::detach $sock
    tpool::post -detached $pool [list ::httpd::accept $sock $nocgi_config $site_config]
}

set init [subst -nocommands -nobackslashes $init_helper]
append init $worker_script
set pool [tpool::create -minworkers 4 -maxworkers [dict get $nocgi_config max_threads] -idletime 300 -initcmd $init]
set server [socket -server connect [dict get $nocgi_config listen_port]]
set time [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
puts "$time nocgi server started!"
vwait forever