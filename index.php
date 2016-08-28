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
?>
<!DOCTYPE html>
<html>
        
    <head>
	<meta charset="utf-8" />
	<title>Automatic Detection of Information Leakage Vulnerabilities in
	    Web Applications</title>
	<link href="css/home_style.css" rel="stylesheet" />
    </head>
    
    <body>
	<h2>Automatic Detection of Information Leakage Vulnerabilities in Web
	    Applications</h2>
	<hr>

	<div>
	    <form action="index.php" method="get" accept-charset="utf-8">
		<p>URL:<p><input id="field" type="text" name="url" maxlength="1000" autofocus /></p>
		    <p><input id="submit" type="submit" value="Find Information Leaks" /></p>

		    <u>Output style:</u>
		    <br/>
		    <div class="ddown">
			<select name="output_style" size="3">
			<option value="table"
			<?php
      			if(isset($_GET['output_style'])){
          		if($_GET['output_style'] === 'table'				   
                       	    || empty($_GET['output_style'])
                       	    || (($_GET['output_style'] !== 'table')
                               && ($_GET['output_style'] !== 'json')
                               && ($_GET['output_style'] !== 'pentest')))
                       	    echo 'selected';
                } else {
                    $_GET['output_style'] = 'table';
                    echo 'selected';
                } ?>>Table</option>
			<option value="json"
			<?php
      			if(isset($_GET['output_style'])){
			    if($_GET['output_style'] === 'json')
    			        echo 'selected';
                } ?>>JSON</option>
			<option value="pentest"
			<?php
                if(isset($_GET['output_style'])){
                    if($_GET['output_style'] === 'pentest')
                        echo 'selected';
                } ?>>Penetration Tester</option>
		    </select>
		    </div>
		    
	    </form>
	</div>
	<hr/>

	<div id="center">
	    <?php include 'main.php' ?>
	    
	</div>

	<hr/><br/>
	<p>by Yakup Ates</p>
    </body>
    
</html>
