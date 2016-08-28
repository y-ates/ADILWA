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

/*
 * @short: Replaces all characters that do not match the whitelist
 * @var input: String that has to be filtered
 * @algorithm: Using preg_replace all occurences that are
 * * NOT a-z A-Z 0-9 = _ : or - will be replaced with a space
 * * --This will be used as a filter for "untrusted" wordlists
 */
function filter_wordlist($input){
    return preg_replace("/[^a-zA-Z0-9=_\-:.\s]/", "#!Filter!!#", $input);
}

?>