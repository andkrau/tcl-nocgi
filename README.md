tcl-nocgi
========

This is a a multi-threaded backend HTTP server that allows one to embed the Tcl programming language into HTML.
The "nocgi" comes from eliminating the use of fastcgi/cgi/scgi to communicate with the frontend server.

Each request is dispatched to be parsed and served by a dedicated thread.
The threading is directly borrowed from [tcl-scgi](https://github.com/gahr/tcl-scgi). 
Improvements in speed were made by handing off processing to the dedicated thread earlier and using persistent connections throughout the life of the thread.

User scripts consist of pure HTML code with interleaved Tcl scripts enclosed in &lt;? and ?&gt; tags.

## Usage

```html
tclsh86.exe C:\somePath\tcl-nocgi.tcl C:\somePath\example.ini
```

The config file requires the following options:

    listen_port
    Listen on the specified port number.
    
    max_threads
    Maximum number of threads.
    If the number of requests exceeds this number, they will wait until a thread is freed.
    
    site_root
    Use this path as a search base for scripts.
    
    start_tag
    Beginning tag for enclosing embedded Tcl code.
    
    end_tag
    Ending tag for enclosing embedded Tcl code.
    
    crypto_key
    64 character hex string used in cookie encryption/decryption.
    
The tcl-nocgi.tcl software requires Tcl 8.6 as well as the Thread, ncgi, and inifile extensions. These extensions are all included with Tcllib.

The following special commands are available:

    echo
        Equivalent to 'puts' but returns the output within the HTML.
        Example:
        echo "cheese and rice"
   
    include
        Includes and evaluates another THP script.
        The script inherits the variable scope of the line on which the include occurs.
        Example:
        include /menu/menu.thp

    readfile
        Inserts plain HTML into the document.
        Other than being faster than include, this should give the same output.
        Example:
        readfile /public/header.htm
        
These commands can be followed by "body", "cookie", and "query":

    existRequest
        Checks to see if a value exists within the request. Returns true or false.
        Example:
        existRequest query lookfor

    getRequest
        Retrieves a value from within the request.
        Example:
        getRequest query lookfor

    setRequest
        Overrides a value for the request.
        Example:
        setRequest cookie token $token

These commands can be followed by "cookie" and "type":

    existResponse
        Checks to see if a value exists within the response. Returns true or false.
        Example:
        existResponse type

    getResponse
        Retrieves a value from within the response.
        Example:
        getResponse cookie token

    setResponse
        Sets a value for the response.
        Example:
        setResponse type "image/jpeg"

Additionally, the following variables are available to client scripts:

    httpd::request
        A dictionary with the request.

    httpd::response
        A dictionary with the response.

Short tags are also available by using a combination of an opening tag &lt;? and various symbols:

    Prints a variable or result of expression: <?=$variable?> or <?=2+2?>
    Executes a THP script inline: <?+/path/scriptName.thp?>
    Executes Tcl command and prints the result: <?![puts "something"]?>