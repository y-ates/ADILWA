<?php

/*
 *   Automatic Detection of Information Leakage Vulnerabilities in
 *   Web Applications.
 *   
 *   Copyright (C) 2015-2016 Yakup Ates <Yakup.Ates@rub.de>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


class Control{
    public $to_analyse = TRUE;
    
    private $url; 		/* controlled by client */
    private $out_style; /* controlled by client */
    private $source; 	/* controlled by website */
    private $header; 	/* controlled by website */

    /*
     * Set this manually to filter local IP addresses!
     */
    private $bcast ;//= "192.168.0.255"; 
    private $smask ;//= "255.255.255.0";

    
    public function __construct($url, $out_style){
        $this->url = $url;
        $this->url = $this->checkURL($this->url);

        if($this->url !== FALSE){
            if($this->checkRedir() === TRUE){
                /* URL seems to be OK. Set source code. */
                $this->setSource();
            }
        } else {
            $this->to_analyse = FALSE;
            return NULL;
        }

        /*
         * If the URL was valid and the source code is set. Set the output style
         * for the View.
         */
        if(!empty($this->source)){
            /* User defined output style */
            $this->out_style = $out_style;
        } else {
            echo("Sorry, the given address has no source code.<br />");
            $this->to_analyse = FALSE;
            return NULL;
        }
    }   

    /*
     * Function to access the private variable $out_style, which defines the
     * output style 
     */
    public function getOutputStyle(){
        return $this->out_style;
    }
    
    /*
     * Function to access the private variable $url
     */    
    public function getURL(){
        return $this->url;
    }

    /*
     * Function to access the private variable $source
     */
    public function getSource(){
        return $this->source;
    }

    /* @short: Get source code of given URL.
     * @var options: Defines settings for the cURL connection
     * @var con: The cURL connection
     * @algorithm: Connects to the global variable $url. Gets content of the
     * * website. Saves content to the global variable $source
     */
    private function setSource(){
        $con = curl_init($this->url);

        $user_agent  = "Mozilla/5.0 (Windows; U; Windows NT ";
        $user_agent .= "5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1";
        
        $options = array(
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_AUTOREFERER    => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT	   => $user_agent,
            CURLOPT_CONNECTTIMEOUT => 10,    
            CURLOPT_TIMEOUT        => 10
        );

        /* Use settings defined in $options for the connection */
        curl_setopt_array($con, $options);
        /* Save content */
        $this->source = curl_exec($con);
        curl_close($con);

        return;
    }

    /* @short: Do not allow redirects to foreign hosts.
     * @var url_host: Defines the host
     * @var redir_host: Holds destination host of the redirect
     * @algorithm: Check whether there is a redirect. If there is a redirect,
     * * check its destination. Do only allow destinations which point to the same
     * * host. 
     */
    private function checkRedir(){
        $data = $this->header[0];
        $info = $this->header[1];
        $header = substr($data, 0, $info['header_size']);
        if($info['http_code']>=300 && $info['http_code']<=308){
            preg_match("!\r\n(?:Location|URI): *(.*?) *\r\n!", $header, $redir);

            if(!empty($redir[1])){
                $tmp = $this->checkURL($redir[1]);
                if($tmp !== FALSE){
                    $redir_host = parse_url($this->checkURL($redir[1]));
                } else {
                    echo(" (Redirect)<br />");
                    return FALSE;
                }
                
                //$redir_host = parse_url($redir[1]);
                $url_host = parse_url($this->url);

                if(empty($redir_host['host']) || empty($url_host['host']))
                    return TRUE;
                
                if($url_host['host'] === $redir_host['host']){
                    return TRUE;
                } else {
                    return FALSE;
                }
            } else {
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    /* @short: Returns header fields.
     * @var result: Contains header fields
     * @var con: The cURL connection
     * @var options: Defines settings for the cURL connection 
     */
    private function setHeader($url){
        $con = curl_init($this->url);
            
        $user_agent  = "Mozilla/5.0 (Windows; U; Windows NT ";
        $user_agent .= "5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1";

        $options = array(
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT	   => $user_agent,
            CURLOPT_CONNECTTIMEOUT => 10,    
            CURLOPT_TIMEOUT        => 10      
        );

        curl_setopt_array($con, $options);
        $data = curl_exec($con);
        $info = curl_getinfo($con);

        $result = array(
            '0' => $data,
            '1' => $info
        );
        $this->header = $result;
        return $result;
    }
    
    /*
     * @short: Add HTTP scheme to the URL.
     * @var url: The URL which will get the scheme added
     * @algorithm: Is the scheme specified? If not add it, else leave it as it
     * * is. 
     */
    private function addHTTP($url, $scheme = 'http://'){
        return parse_url($url, PHP_URL_SCHEME) === null ? $scheme . $url : $url;
    }

    /*
     * @short: Validate the given URL.
     * @var url: The URL which is going to be analyzed
     * @var url_head: Contains respone headers
     * @algorithm: Did the user specify the protocol?
     * * If not, do it with 'http://'.
     * * Are all characters within the URL valid?
     * * Does the URL exist? Does it respond?
     * * Check the HTTP status code - if it's 404 the given address
     * * probably does not exist -> exit.
     * * Is a local/localhost address given? If so, exit.
     * * Is a port other than 80 (HTTP) or 443 (HTTPS) specified? If so, exit.
     * * Do not allow any username/passwords within the given url.
     *
     * IMPORTANT: $url may be edited.
     */
    private function checkURL($url){
        if(!empty($url)){                
            /* Does the URL have illegal characters? */
            $url = filter_var($url, FILTER_SANITIZE_URL);

            /* Protocol specified? */
            $url = $this->addHTTP($url);

            /* Is the URL valid? */
            if((filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_HOST_REQUIRED) === FALSE)){
                echo("Sorry, this does not look like a valid URL.");
                return FALSE;
            } else {
                $url_tmp = parse_url($url);

                if(isset($url_tmp['host'])){
                    if(($url_tmp['host'] === '127.0.0.1') || ($url_tmp['host'] === 'localhost')){
                        echo("Scanning localhost is not allowed.");
                        return FALSE;
                    }

                    $regex = "/\b(([1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|";
                    $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|";
                    $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b/";
                    $ip;
                    if(preg_match($regex, $url_tmp['host'], $ip) === 1){
                        /*
                         * Broadcast and mask are hardcoded for now.
                         * With this check the program denies that an attacker
                         * is able to "scan" the local network of the
                         * server. We could get the $bcast and $smask out of
                         * ifconfig or ipconfig. We could also request it by the
                         * admin in a setup script or similar.
                         * --- TODO ---
                         */
                        $bcast = $this->bcast;
                        $smask = $this->smask;
                        if($this->IP_isLocal($url_tmp['host'], $bcast, $smask) === TRUE){
                            echo("Sorry, the given address is not reachable.");
                            return FALSE;
                        }
                    }
                }

                /* Only allow HTTP and HTTPS ports in the URL. */
                if(isset($url_tmp['port'])){
                    if(($url_tmp['port'] != '80')
                       && ($url_tmp['port'] != '443')){
                        echo("Sorry, I am not able to communicate on that port.");
                        return FALSE;
                    }
                }
                
                if(isset($url_tmp['user']) || isset($url_tmp['pass'])){
                    echo("You should not tell me your username/password for other services.");
                    return FALSE;
                } else {
                    /* URL seems legit. Check headers now. */
                    $this->setHeader($url);
                    $status_code = $this->header[1];

                    if(empty($status_code)){
                        echo("Sorry, the given address is not reachable.");
                        return FALSE;
                    } else if($status_code['http_code'] != '404'){
                        /* Everything seems fine! */
                        $this->url = $url; 
                        return $url;
                    } else {
                        echo("Sorry, the given address is not reachable. (404)");
                        return FALSE;
                    }
                }
            }
        } /* else: no URL given - nothing to do. */
    }

    /* @short: Is the given IP local?
     * @var ip: IP to analyze
     * @var bcast: Broadcast address of server
     * @var smask: Mask address of server
     * @algorithm: Calculates whether $ip is in the local network.
     * * Actually it only calculates if it _could_ be in the local network with
     * * the given broadcast address and mask.
     * * Returns boolean TRUE, if it could.
     */
    private function IP_isLocal($ip, $bcast, $smask){
        if(empty($bcast) || empty($smask) || empty($ip))
            return NULL;
                
        $bcast = ip2long($bcast);
        $smask = ip2long($smask);
        $ip = ip2long($ip);

        $nmask = $bcast & $smask;
        
        return (($ip & $smask) == ($nmask & $smask));
    }
}

?>
