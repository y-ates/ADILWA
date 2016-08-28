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

include 'libs/analyser.php';

class Model{

    private $controller;
    private $DOM;
    private $source;
    private $analyser;

    private $cms;
    private $cms_name;
    private $cms_found = FALSE;
    private $plugins;
    private $jslib;
    private $comment;
    private $input;
    private $meta;
    private $ip;
    private $email;
    private $cc;
    private $sqlQuery;
    private $svn_git;
    private $path;
    private $misc;
    
    public function __construct($controller){
        $this->controller = $controller;      
        $this->source = $this->controller->getSource();

        $this->analyser = new Analyser($this->source);
        $this->DOM = $this->analyser->getDOM();
        
        $this->cms = $this->analyser->analyse_cms();
        
        if(!empty($this->cms)){
            $this->cms_name = $this->analyser->analyse_cms(FALSE);
            $this->plugins = $this->analyser->analyse_plugins($this->cms_name);
        }

        $this->jslib = $this->analyser->analyse_JSLib();
        $this->comment = $this->analyser->analyse_comments();
        $this->input = $this->analyser->analyse_inputs();
        $this->meta = $this->analyser->analyse_metas();
        /*
         * TODO. analyse_generic() is currently not filtered enough. Too many false
         * positives. Thus its commented out.
         */
        //$this->misc = $this->analyser->analyse_generic();
        $this->ip = $this->analyser->find_IP($this->source);
        $this->email = $this->analyser->find_email($this->source);
        $this->path = $this->analyser->find_path($this->controller->getURL());
        //$this->cc = $this->analyser->find_CC($this->source);
        $this->svn_git = $this->analyser->find_SVN_GIT($this->source);
        /*
         * TODO. find_SQLQuery($this->source) too many false positives.
         * Thus its commented out.
         */
        //$this->sqlQuery = $this->analyser->find_SQLQuery($this->source);
    }

    /* @short: Returns generic findings */
    public function getMisc(){
        return $this->misc;
    }
    
    /* @short: Returns source code of the target. */
    public function getSource(){
        return $this->source;
    }
    
    /* @short: Returns all nodes which hints the CMS used by the target.*/
    public function getCMS(){
        return $this->cms;
    }

    /* @short: Returns a list of used CMS plugins by the target. */
    public function getPlugin(){
        return $this->plugins;
    }

    
    /* @short: Returns all interesting comments, placed in the DOM. */
    public function getComment(){
        return $this->comment;
    }

    /* @short: Returns all interesting input fields as nodes. */
    public function getInput(){
        return $this->input;
    }

    /* @short: Returns all interesting meta tags as nodes. */
    public function getMeta(){
        return $this->meta;
    }

    /* @short: Returns all path' found in the DOM. */
    public function getPath(){
        return $this->path;
    }

    /* @short: Returns all IPs found in the DOM. */
    public function getIP(){
        return $this->ip;
    }

    /* @short: Returns all E-Mail addresses found in the DOM. */
    public function getEmail(){
        return $this->email;
    }

    /* @short: Returns all creditcard numbers found in the DOM. */
    public function getCC(){
        return $this->cc;
    }

    /* @short: Returns all MySQL queries found in the DOM.*/
    public function getSQLQuery(){
        return $this->sqlQuery;
    }

    /* @short: Returns all SVN/GIT files/references found in the DOM. */
    public function getSVN_GIT(){
        return $this->svn_git;
    }

    /* @short: Returns all Javascript libraries found in the DOM. */
    public function getJSLib(){
        return $this->jslib;
    }

    /* @short: Return DOM*/
    public function getDOM(){
        return $this->DOM;
    }
}

?>
