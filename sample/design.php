<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

function design($title) {
	global $doc;
	$doc = new \TRP\HealDocument\HealDocument();
	
	$html = $doc->el('html');
	$html->at(['lang'=>'en']);
	
	$head = $html->el('head');
	$head->el('title')->te($title.' :: simple-auth');
	$head->el('meta',['charset'=>'UTF-8']);
	
	$body = $html->el('body');
	$body->el('h2')->te($title);
	
	register_shutdown_function('design_echo');
	
	return $body;
}

function design_echo() {
	global $doc;
	echo $doc;
}
