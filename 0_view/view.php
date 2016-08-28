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


class View{
    
    private $model;
    private $controller;

    public function __construct($model, $controller){
        $this->model = $model;
        $this->controller = $controller;

        switch($this->controller->getOutputStyle()){
        case "table":
            $this->table_view();
            break;
        case "json":
            $this->json_view();
            break;
        case "pentest":
            $this->pentest_view();
            break;
        default:
            $this->table_view(); /* Normally it should never come here */
            break;
        }
    }
    
    /*
     * @short: Generate tables and insert results made by Model.
     * @algorithm: Gets the results from Model. Generates a table if the result
     * is not empty. Loops over all nodes and inserts these into the table.
     * 
     * TODO: Make small tables to be placed to each other.
     */
    public function table_view(){
        $cnt = 0;
        $nodes = $this->model->getMeta();
        
        if(!empty($nodes[0])){
            foreach($nodes as $n){
                foreach($n as $node){
                    $tmp = 0;
                    foreach($node->attributes as $attribute){
                        $tmp++;
                        if($tmp > $cnt){
                            $cnt = $tmp;
                        }
                    }
                }
            }
            
            echo "<br/>";
            echo "<table style='width:100%'>\r\n";
            echo "<caption><b>Meta Tags</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }
            echo "</tr>\r\n";
            
            foreach($nodes as $n){
                if(!empty($n->length)){
                    foreach($n as $node){
                        echo "<tr>\r\n";
                        echo "<td>" . $node->nodeName . "</td>\r\n";
                        
                        foreach($node->attributes as $attribute){
                            echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                            echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                        }
                        
                        echo "</tr>\r\n";
                    }
                }
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $nodes = $this->model->getComment();
        if(!empty($nodes[0])){
            echo "<br/>";
            echo "<table style='width:100%'>\r\n";
            echo "<caption><b>Comments</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            echo "<th>Value</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($nodes as $n){
                echo "<tr>\r\n";
                echo "<td>comment</td>\r\n";
                echo "<td>" . htmlspecialchars($n) . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $cnt = 0;
        $nodes = $this->model->getInput();
        if(!empty($nodes[0])){
            foreach($nodes as $node){
                $tmp = 0;
                foreach($node->attributes as $attribute){
                    $tmp++;
                    if($tmp > $cnt){
                        $cnt = $tmp;
                    }
                }
            }
        }

        if(!empty($nodes)){
            echo "<br/>";
            echo "<table style='width:100%;'>\r\n";
            echo "<caption><b>Inputs</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }
            echo "</tr>\r\n";
            
            foreach($nodes as $node){
                echo "<tr>\r\n";
                echo "<td>" . $node->nodeName . "</td>\r\n";
                
                foreach($node->attributes as $attribute){
                    echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                    echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                }
                
                echo "</tr>\r\n";
            }

            echo "</table>\r\n";
        }



        /****************************************/
        $cnt = 0;
        $nodes = $this->model->getCMS();
        $isVuln = $nodes['isVuln'];
        $version = $nodes['version'];
        $nodes = $nodes['node'];
        if(!empty($nodes[0])){
            foreach($nodes as $node){
                $tmp = 0;
                foreach($node->attributes as $attribute){
                    $tmp++;
                    if($tmp > $cnt){
                        $cnt = $tmp;
                    }
                }
            }
        }

        if(!empty($nodes[0])){
            echo "<br/>";
            echo "<table style='width:100%;'>\r\n";
            echo "<caption><b>CMS</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }
            
            if($isVuln === TRUE)
                echo "<th>isVuln</th>\r\n";
            
            echo "</tr>\r\n";
            
            foreach($nodes as $node){
                $column_position = 0;
                echo "<tr>\r\n";
                echo "<td>" . $node->nodeName . "</td>\r\n";
                
                foreach($node->attributes as $attribute){
                    echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                    echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                    $column_position++;
                }

                while($column_position < $cnt){
                    echo "<td></td>\r\n";
                    echo "<td></td>\r\n";
                    $column_position++;
                }
                if($isVuln === TRUE)
                    echo "<td>" . $isVuln . "</td>\r\n";
                echo "</tr>\r\n";
            }
                    
            echo "</table>\r\n";
        }

        /****************************************/
        $cnt = 0;
        $nodes = $this->model->getPlugin();
        $vulnLink = $nodes['vulnCheck'];
        $nodes = $nodes['node'];
        
        if(!empty($nodes[0])){
            foreach($nodes as $node){
                $tmp = 0;
                foreach($node->attributes as $attribute){
                    $tmp++;
                    if($tmp > $cnt){
                        $cnt = $tmp;
                    }
                }
            }
        }

        if(!empty($nodes[0])){
            $vuln_cnt = 0;
            
            echo "<br/>";
            echo "<table style='width:100%;'>\r\n";
            echo "<caption><b>Plugins</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }
            
            if($vulnLink[$vuln_cnt] !== NULL)
                echo "<th>Vuln?</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($nodes as $node){
                $cnt++;
                echo "<tr>\r\n";
                echo "<td>" . $node->nodeName . "</td>\r\n";
                
                foreach($node->attributes as $attribute){
                    echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                    echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                }

                if($vulnLink[$vuln_cnt] !== NULL)
                    echo "<td><a href='" . $vulnLink[$vuln_cnt] . "'>X</a></td>\r\n";
                
                echo "</tr>\r\n";
            }
                    
            echo "</table>\r\n";
        }

        /****************************************/
        $cnt = 0;
        $cnt_version = 0;
        $cnt_vuln = 0;
        $c = 0;
        $nodes = $this->model->getJSLib();
        $vuln = $nodes['isVuln'];
        $version = $nodes['version'];
        $nodes = $nodes['nodes'];
        
        if(!empty($nodes[0])){
            foreach($nodes as $node){
                $tmp = 0;
                foreach($node->attributes as $attribute){
                    $tmp++;
                    if($tmp > $cnt){
                        $cnt = $tmp;
                    }
                }
                
                if((!empty($version[$c])) &&
                   ($version[$c] !== "N/A")){
                    /* Count how many versions are detected */
                    $cnt_version++;
                }
                if((!empty($vuln[$c])) &&
                   ($vuln[$c] !== "N/A")){
                    $cnt_vuln++;
                }
                $c++;
            }
        }

            
        if(!empty($nodes[0])){
            echo "<br/>";
            echo "<table style='width:100%;'>\r\n";
            echo "<caption><b>Javascript libraries</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }

            /* Are any versions detected? */
            if($cnt_version > 0){
                echo "<th>Version</th>\r\n";
            }
            if($cnt_vuln > 0){
                echo "<th>isVuln</th>\r\n";
            }
            echo "</tr>\r\n";

            $i = 0;
            $j = 0;
            foreach($nodes as $node){
                $column_position = 0;
                echo "<tr>\r\n";
                echo "<td>" . $node->nodeName . "</td>\r\n";
                
                foreach($node->attributes as $attribute){
                    echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                    echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                    $column_position++;
                }

                while($column_position < $cnt){
                    echo "<td></td>\r\n";
                    echo "<td></td>\r\n";
                    $column_position++;
                }
                    
                if((!empty($version[$i])) &&
                   ($version[$i] !== "N/A")){
                    echo "<td>" . $version[$i] . "</td>\r\n";
                } /*else {
                    echo "<td></td>\r\n";
                    }*/
                if((!empty($vuln[$j])) &&
                   ($vuln[$j] !== "N/A")){
                    echo "<td>" . $vuln[$j] . "</td>\r\n";
                } /*else {
                    echo "<td></td>\r\n";
                    }*/
                
                $i++;
                $j++;
                
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }


        /****************************************/
        $cnt = 0;
        $nodes = $this->model->getMisc();
        if(!empty($nodes[0])){
            foreach($nodes as $node){
                $tmp = 0;
                foreach($node->attributes as $attribute){
                    $tmp++;
                    if($tmp > $cnt){
                        $cnt = $tmp;
                    }
                }
            }
        }

            
        if(!empty($nodes[0])){
            echo "<br/>";
            echo "<table style='width:100%;table-layout:fixed;'>\r\n";
            echo "<caption><b>Misc</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Tag</th>\r\n";
            for($i=0;$i<$cnt;$i++){                           
                echo "<th>Attribute</th>\r\n";
                echo "<th>Value</th>\r\n";
            }
            echo "</tr>\r\n";
            
            foreach($nodes as $node){
                echo "<tr>\r\n";
                echo "<td>" . $node->nodeName . "</td>\r\n";
                
                foreach($node->attributes as $attribute){
                    echo "<td>" . htmlspecialchars($attribute->name) . "</td>\r\n";
                    echo "<td>" . htmlspecialchars($attribute->value) . "</td>\r\n";
                }
                
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        echo "<div>\r\n";
        
        $ips = $this->model->getIP(); 
        if(!empty($ips)){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>IPs</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>IP</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($ips as $ip){
                echo "<tr>\r\n";
                echo "<td>" . $ip . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $emails = $this->model->getEmail(); 
        if(!empty($emails)){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>E-Mail</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>E-Mail address</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($emails as $email){
                echo "<tr>\r\n";
                echo "<td>" . $email . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        
        /****************************************/
        $CCs = $this->model->getCC(); 
        if(!empty($CCs)){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>Creditcard</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Creditcard number</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($CCs as $CC){
                echo "<tr>\r\n";
                echo "<td>" . $CC . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $SQL = $this->model->getSQLQuery(); 
        if(!empty($SQL)){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>SQL Queries</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>Query</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($SQL as $query){
                echo "<tr>\r\n";
                echo "<td>" . $query . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $SVN_GIT = $this->model->getSVN_GIT(); 
        if(!empty($SVN_GIT)){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>SVN / GIT</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>SVN / GIT</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($SVN_GIT as $svn_git){
                echo "<tr>\r\n";
                echo "<td>" . $svn_git . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        /****************************************/
        $path = $this->model->getPath();
        if(!empty($path[0])){
            echo "<br/>";
            echo "<table>\r\n";
            echo "<caption><b>Paths found</b></caption>\r\n";
            echo "<tr>\r\n";
            echo "<th>path</th>\r\n";
            echo "</tr>\r\n";
            
            foreach($path as $p){
                echo "<tr>\r\n";
                echo "<td>" . $p . "</td>\r\n";
                echo "</tr>\r\n";
            }
            
            echo "</table>\r\n";
        }

        echo "</div>\r\n";
    }

    
    /*
     * @short: Generate JSON output of the results made by Model.
     * @algorithm: Gets the results from Model. Generates an array if the result
     * is not empty. Loops over all nodes and inserts these into the
     * array. Then it prints the filled array in JSON format.
     * 
     * TODO: Maybe the JSON outputs should have captions.
     */
    public function json_view(){
        echo "</div><div id='json'><pre>";
        $nodes = $this->model->getMeta();
        if(!empty($nodes[0])){
            echo "<br/>\r\n";
        
            foreach($nodes as $n){
                if(!empty($n->length)){
                    $node_ = array();
                    
                    foreach($n as $node){
                        $node_['found'] = "meta";
                        $node_['tag'] = $node->nodeName;
                        foreach($node->attributes as $attribute){
                            $node_['attribute'][] = $attribute->name;
                            $node_['value'][] = $attribute->value;
                        }
                                          
                    }
                    echo htmlspecialchars(json_encode($node_,
                                                      JSON_PRETTY_PRINT |
                                                      JSON_UNESCAPED_SLASHES));
                    echo "<br/>\r\n";
                }
            }
        }

        /****************************************/
        $nodes = $this->model->getComment();
        if(!empty($nodes[0])){
            echo "<br/>\r\n";
            $node_ = array();
        
            foreach($nodes as $node){
                $node_['found'] = "comment";
                $node_['tag'] = "comment";
                $node_['value'] = $node;
                
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $nodes = $this->model->getInput();
        if(!empty($nodes[0])){
            echo "<br/>\r\n";
            
            foreach($nodes as $node){
                $node_ = array();
                $node_['found'] = "input";
                $node_['tag'] = $node->nodeName;
                foreach($node->attributes as $attribute){
                    $node_['attribute'][] = $attribute->name;
                    $node_['value'][] = $attribute->value;
                }
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
            
        }

        /****************************************/
        $nodes = $this->model->getCMS();
        $isVuln = $nodes['isVuln'];
        $version = $nodes['version'];
        $nodes = $nodes['node'];

        if(!empty($nodes[0])){
            echo "<br/>\r\n";
            $i = 0;
            
            foreach($nodes as $node){
                $node_ = array();
                $node_['found'] = "cms";
                $node_['tag'] = $node->nodeName;
                foreach($node->attributes as $attribute){
                    $node_['attribute'][] = $attribute->name;
                    $node_['value'][] = $attribute->value;
                }

                if(!empty($version)){
                    $node_['CMS_version'] = $version;
                } else {
                    $node_['CMS_version'] = "N/A";
                }

                if($isVuln === TRUE)
                    $node_['isVuln'] = $isVuln;
                    
                $i++;
                
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $nodes = $this->model->getPlugin();
        $vulnLink = $nodes['vulnCheck'];
        $nodes = $nodes['node'];
        
        if($nodes !== NULL){
            echo "<br/>\r\n";
            $i = 0;
            
            foreach($nodes as $node){
                $node_ = array();
                $node_['found'] = "plugin";
                $node_['tag'] = $node->nodeName;
                foreach($node->attributes as $attribute){
                    $node_['attribute'][] = $attribute->name;
                    $node_['value'][] = $attribute->value;
                }

                if($vulnLink[$i] !== NULL){
                    $node_['vulnCheck'][] = $vulnLink[$i];
                } else {
                    $node_['vulnCheck'][] = "N/A";
                }

                $i++;
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $nodes = $this->model->getJSLib();
        $isVuln = $nodes['isVuln'];
        $version = $nodes['version'];
        $nodes = $nodes['nodes'];

        if(!empty($nodes)){
            echo "<br/>\r\n";
            $node_ = array();
            $i = 0;
            
            foreach($nodes as $node){
                $node_['found'] = "javascript_lib";
                $node_['tag'] = $node->nodeName;
                foreach($node->attributes as $attribute){
                    $node_['attribute'] = $attribute->name;
                    $node_['value'] = $attribute->value;
                }
                
                if((!empty($version[$i])) &&
                   ($version[$i] !== "N/A")){
                    $node_['version'] = $version[$i];
                } else {
                    unset($node_['version']);
                } 

                if((!empty($isVuln[$i])) &&
                   ($isVuln[$i] !== "N/A")){
                    $node_['isVuln'] = $isVuln[$i];
                } else {
                    unset($node_['isVuln']);
                }
                
                $i++;
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $nodes = $this->model->getMisc();
        if(!empty($nodes[0])){
            echo "<br/>\r\n";
        
            foreach($nodes as $node){
                $node_ = array();
                $node_['found'] = "misc";
                $node_['tag'] = $node->nodeName;
                foreach($node->attributes as $attribute){
                    $node_['attribute'][] = $attribute->name;
                    $node_['value'][] = $attribute->value;
                }
                echo htmlspecialchars(json_encode($node_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $ips = $this->model->getIP();
        if(!empty($ips[0])){
            echo "<br/>\r\n";
            $IPs_ = array();
        
            foreach($ips as $ip){
                $IPs_['found'] = "ip";
                $IPs_['value'] = $ip;
                echo htmlspecialchars(json_encode($IPs_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $emails = $this->model->getEmail();
        if(!empty($emails)){
            echo "<br/>\r\n";
            $emails_ = array();
        
            foreach($emails as $email){
                $emails_['found'] = "e-mail";
                $emails_['value'] = $email;
                echo htmlspecialchars(json_encode($emails_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $CCs = $this->model->getCC();
        if(!empty($CCs)){
            echo "<br/>\r\n";
            $CCs_ = array();
        
            foreach($CCs as $CC){
                $CCs_['found'] = "credit_card_number";
                $CCs_['value'] = $CC;
                echo htmlspecialchars(json_encode($CCs_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $SQL = $this->model->getSQLQuery();
        if(!empty($SQL)){
            echo "<br/>\r\n";
            $queries_ = array();
        
            foreach($SQL as $query){
                $queries_['found'] = "sql_query";
                $queries_['value'] = $query;
                echo htmlspecialchars(json_encode($queries_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $SVN_GIT = $this->model->getSVN_GIT(); 
        if(!empty($SVN_GIT)){
            echo "<br/>\r\n";
            $repos_ = array();
        
            foreach($SVN_GIT as $repo){
                $repos_['found'] = "svn/git";
                $repos_['value'] = $repo;
                echo htmlspecialchars(json_encode($repos_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        /****************************************/
        $path = $this->model->getPath(); 
        if(!empty($path)){
            echo "<br/>\r\n";
            $paths_ = array();
        
            foreach($path as $p){
                $paths_['found'] = "path";
                $paths_['value'] = $p;
                echo htmlspecialchars(json_encode($paths_,
                                                  JSON_PRETTY_PRINT |
                                                  JSON_UNESCAPED_SLASHES));
                echo "<br/>\r\n";
            }
        }

        echo "</pre>";
    }

    /*
     * @short: Return the whole source code. Color the findings (whole tags
     * * and/or only strings).
     */
    public function pentest_view(){
        /*
         * The whole source code of a webpage will be printed here. To format
         * the output properly, we need to "overwrite" the css configuration for
         * the id "center", which is a div that holds all generated data.
         * - We dont want the output to be centered.
         * - We want to have tabs properly set (code is indented) as well as the
         *   newlines. 
         */
        $DOM = $this->model->getDOM();
        $source = htmlspecialchars($DOM->saveHTML());

        
        /* nodes */
        $meta = $this->model->getMeta();
        $comment = $this->model->getComment();
        $input = $this->model->getInput();
        $cms = $this->model->getCMS();
        $plugins = $this->model->getPlugin();
        $plugins = $plugins['node'];
        $jslib = $this->model->getJSLib();
        $jslib = $jslib['nodes'];
        $misc = $this->model->getMisc();
        
        /* strings */
        $ip = $this->model->getIP();
        $email = $this->model->getEmail();
        $cc = $this->model->getCC();
        $sql = $this->model->getSQLQuery();
        $SVN_GIT = $this->model->getSVN_GIT();
        $path = $this->model->getPath();

        if(!empty($meta[0])){
            foreach($meta as $meta_nodes){
                foreach($meta_nodes as $meta_node){
                    $needle = htmlspecialchars($DOM->saveHTML($meta_node));
                    $needle = preg_replace("/\n/", "", $needle);
                    $replace = "<font color='red'>" . $needle . "</font>";;
                
                    $source = str_replace($needle, $replace, $source);
                }
            }
        }

        if(!empty($comments[0])){
            foreach($comment as $comm){
                $needle = htmlspecialchars($comm);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($input[0])){
            foreach($input as $in){
                $needle = htmlspecialchars($DOM->saveHTML($in));
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($cms[0])){
            foreach($cms as $cms_finding){
                $needle = htmlspecialchars($DOM->saveHTML($cms_finding));
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($plugins[0])){
            foreach($plugins as $plugin){
                $needle = htmlspecialchars($DOM->saveHTML($plugin));
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($jslib[0])){
            foreach($jslib as $lib){
                $needle = htmlspecialchars($DOM->saveHTML($lib));
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($misc[0])){
            foreach($misc as $other_findings){
                $needle = htmlspecialchars($DOM->saveHTML($other_findings));
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($ip[0])){
            foreach($ip as $found_ips){
                $needle = htmlspecialchars($found_ips);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($email[0])){
            foreach($email as $mail_address){
                $needle = htmlspecialchars($mail_address);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($cc[0])){
            foreach($cc as $found_CCs){
                $needle = htmlspecialchars($found_CCs);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($sql[0])){
            foreach($sql as $found_queries){
                $needle = htmlspecialchars($found_queries);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($SVN_GIT[0])){
            foreach($SVN_GIT as $svn_git_findings){
                $needle = htmlspecialchars($svn_git_findings);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }

        if(!empty($path[0])){
            foreach($path as $found_path){
                $needle = htmlspecialchars($found_path);
                $needle = preg_replace("/\n/", "", $needle);
                $replace = "<font color='red'>" . $needle . "</font>";;
                
                $source = str_replace($needle, $replace, $source);
            }
        }
        
        /*
         * Dirty solution for now.
         * TODO: Clean CSS etc. up.
         */
        echo "</div><div id='pentest'><pre>" . $source . "</pre>";
    }

}


?>
