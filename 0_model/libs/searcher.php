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

include 'reader.php';

class Searcher{
    
    private $xpath;
    private $DOM;     /* $DOM is not used. */
    
    public function __construct($source){
        libxml_use_internal_errors(true);
        /* SETUP DOM */
        $doc = new DOMDocument();
        $doc->loadHTML($source);

        $this->DOM = $doc;
        
        /* SETUP XPath Object */
        $this->xpath = new DOMXPath($doc);
    }
    

    /*
     * @short: Return DOM
     */
    public function getDom(){
        return $this->DOM;
    }
    
    /*
     * @short: Search $word in all attributes of the given DOM
     */
    public function in_attr($word){
        $nodes = $this->xpath_search("//*[@" . $word . "]");

        return $nodes;
    }
    
    /*
     */
    public function in_all($word){
        $nodes = $this->xpath_search("//*[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }
    
    /*
     */
    public function in_input($word){
        $nodes = $this->xpath_search("//input[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }
    
    /*
     * @short: Search $word in all meta tags of the given DOM 
     */
    public function in_meta($word){
        $nodes = $this->xpath_search("//meta[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }
    
    /*
     * @short: Search $word in all comments
     */
    public function in_comment($word){
        $nodes = $this->xpath_search("//comment()[contains(., '" . $word . "')]");
        
        return $nodes;
    }
    
    /*
     * @short: Search via XPath through the DOM with the given $query
     * @var xpath: DOMXPath Object
     * @var query: XPath query, which will be used for the DOMXPath Object
     */
    public function xpath_search($query){
        $xpath = $this->xpath;
        $nodes = $xpath->query($query);

        if($nodes->length)
            return $nodes;
        else
            return NULL; /* Query result is empty */
    }


    /*
     * @short: Search all keywords specified with $file in the source specified
     * * with $source 
     * @var lineCount: Count of lines within $file
     * @var line: Output of the selected $i'th line
     * @var offset: Position to search for the next occurence of $line 
     * @var pos: Position of the found string occurence 
     * @var i: Position in $file of the string that is being searched
     * @var found: Holds all findings and their position
     */
    private function searchString($file, $source){
        $lineCount = count(file($file));
        $i = 0;
        $count_occ = 0;
        while($i <= $lineCount){
            ++$i;
            $line = getLine($file, $i);
            $line = preg_replace("/\n/", "", $line);

            if(!empty($line)){
                $offset = 0;

                while(($pos = strpos($source, $line, $offset)) !== FALSE){
                    $offset = $pos + 1;
                    $count_occ++;
                    $found[$count_occ] = $line . "@" . $pos;
                }
            } else {
                continue;
            }
        }
        
        return $found;
    }
}