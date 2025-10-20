<?php

declare(strict_types=1);
require_once('include.php');

$body = design('Two Factor Authentication');
$body->el('a',['href'=>'.'])->te('Back');

$form = $body->el('form',['method'=>'post','action'=>'tfa.script.php']);
$form->el('input',['name'=>'username','required','hidden','value'=>empty($_GET['username']) ? '' : $_GET['username']]);

$form->el('label')->te('2FA code');
$form->el('input', [
    'name' => 'totp',
    'inputmode' => 'numeric',
    'pattern' => '[0-9]{6}',
    'maxlength' => '6',
    'autocomplete' => 'one-time-code'
]);
$form->el('br');

if(isset($_GET['error'])) {
    $form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
    $form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');
