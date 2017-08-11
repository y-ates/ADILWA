
## LICENSE
   Automatic Detection of Information Leakage Vulnerabilities in
   Web Applications.
   
   Copyright (C) 2015-2016 Yakup Ates <Yakup.Ates@rub.de>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.



## INSTALL				
This application is tested on:
```
     Server version: Apache/2.4.10 (Debian)
     Server built:   Nov 28 2015 14:05:48

     PHP 5.6.17-0+deb8u1 (cli) (built: Jan 13 2016 09:10:12) 
     Copyright (c) 1997-2015 The PHP Group
     Zend Engine v2.6.0, Copyright (c) 1998-2015 Zend Technologies
     with Zend OPcache v7.0.6-dev, Copyright (c) 1999-2015, by Zend Technologies
```
You need PHP and a webserver:
```
    $ apt-get install apache2 php
```
There is no DBMS needed, everything is handled with files.
The connection is build with cURL, so it has to be installed. This is done in
Debian with:
       $ apt-get install php5-curl

There is a security function, which needs the broadcast address and mask of the
server. This enables the application to calculate possible local IP
addresses. There is no setup script yet. So you have to manually set it. It can
be set in '0_control/control.php' on lines 35 and 36.
   - It is recommended to set it!
   
An example:
```
    /*
     * Set this manually to filter local IP addresses!
     */
    private $bcast = "192.168.0.255"; 
    private $smask = "255.255.255.0";
```


## OUTPUT
There is a noGUI version of this application. An output could look like this:
```
Array
(
    [0] => {
    "found": "meta",
    "tag": "meta",
    "attribute": [
        "name",
        "content"
    ],
    "value": [
        "author",
        "NAME OF AUTHOR"
    ]
}
    [1] => {
    "found": "meta",
    "tag": "meta",
    "attribute": [
        "http-equiv",
        "content"
    ],
    "value": [
        "Expires",
        ""
    ]
}
    [2] => {
    "found": "meta",
    "tag": "meta",
    "attribute": [
        "name",
        "content"
    ],
    "value": [
        "robots",
        "index, follow"
    ]
}
    [3] => {
    "found": "javascript_lib",
    "tag": "script",
    "attribute": "src",
    "value": "Some JavaScript library"
}
    [4] => {
    "found": "e-mail",
    "value": "test@test.com"
}
    [5] => {
    "found": "path",
    "value": "/path/to/a/file"
}
)
```
Remember, this will be returned and not printed. If you want to test it, you can
replace the return with e.g. print_r(). Those lines are already written down,
so that you only have to uncomment line 306 and comment line 307
of the file 0_view/view.php.
After that you can simply rerun the application and you should see the output
printed in your browser. It is probably not formatted, this is due to your
browser. Just view the source code with "Ctrl + U" and you will see the
formatted one.

As you can see the first output line describes the finding itself (for example
"found": "path"). After that it
will either print the tag with its attributes and values or it prints the
result. This depends on the finding. You can see the difference in the example
above. E.g. the findings of e-mail addresses, paths, creditcards, Git, SQL
queries, IPs will be returned without the tags.
