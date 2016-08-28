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

include 'filter.php';

/*
 * @short: Returns a specific line of a file.
 * @var row: The returned line is specified by $row. First row is
 * * represented by 1.
 * @var file: The file is specified by $file.
 * @var trusted: If trusted is set to false, the line will be filtered.
 * @algorithm: It will read the file starting at the first line until it
 * * reaches line $row. When it is reached, the line will be returned the
 * * search stopped and the file handler closed.
 */
function getLine($file, $row, $trusted=TRUE){
    if(is_readable($file)){
        $reader = fopen($file, "r");
        $readerAt = 0;
                
        if($reader !== FALSE){
            while(($line = fgets($reader)) !== FALSE){
                $readerAt++;
                if($readerAt === $row){
                    fclose($reader);
                    if($trusted === TRUE)
                        return $line;
                    else /* Wordlist is not trusted - filter! */
                        return filter_wordlist($line);
                }
            }
        }
        fclose($reader);
    } else {
        echo("Error: Could not read file.");
        return;
    }
}

?>