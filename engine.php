<?php /*
                  d8b                     d8, d8b        
                  88P              d8P   `8P  88P        
                 d88            d888888P     d88         
?88   d8P d8888b 888   d888b8b    ?88'    88b888   d8888b
d88  d8P'd8P' ?88?88  d8P' ?88    88P     88P?88  d8b_,dP
?8b ,88' 88b  d88 88b 88b  ,88b   88b    d88  88b 88b    
`?888P'  `?8888P'  88b`?88P'`88b  `?8b  d88'   88b`?888P'
                                                         
Volatile, a free key-value pair API

Copyright (c) 2020 Neatnik LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

define('MYSQL_BASE', 'volatile');
define('MYSQL_USER', 'CHANGE_ME');
define('MYSQL_PASS', 'CHANGE_ME');

header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Origin: *");

try {
	$pdo = new PDO('mysql:host=localhost;dbname='.MYSQL_BASE.';charset=utf8mb4', MYSQL_USER, MYSQL_PASS);
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
}
catch(PDOException $e) {
	throw new Exception('Could not connect to database. :-(');
}

function respond($response, $json = null) {
	if($json !== null) {
		header("Content-type: application/json");
		echo json_encode($json, JSON_PRETTY_PRINT);
	}
	else {
		header("Content-type: text/plain");
		echo $response;
	}
	exit;
}

// Check for raw posts, which may be in JSON

$post = file_get_contents('php://input');
$post = json_decode($post, JSON_PRETTY_PRINT);

if($post !== null) {
	
	// we got JSON
	
	$json = array();
	
	if(isset($post['key'])) $_REQUEST['key'] = $post['key'];
	if(isset($post['val'])) $_REQUEST['val'] = $post['val'];
	
	if(isset($post['created'])) $_REQUEST['created'] = true;
	if(isset($post['modified'])) $_REQUEST['modified'] = true;
}


// Define rate limit parameters

$create_interval = 900; // 15 mins
$create_limit = 100;
$read_interval = 900; // 15 mins
$read_limit = 200;

if(isset($_REQUEST['value'])) {
	$_REQUEST['val'] = $_REQUEST['value'];
}

// Create

if(isset($_REQUEST['key']) && isset($_REQUEST['val'])) {
	
	// Rate limit check
	
	$stmt = $pdo->prepare('SELECT timestamp FROM `log` WHERE ip = :ip AND timestamp > DATE_SUB(NOW(), INTERVAL '.$create_interval.' SECOND) ORDER BY timestamp DESC');
	$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
	$data = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
	
	// were there previous requests
	if(count($data) > 0) {
		$recent = count($data);
		header("X-Rate-Limit-Interval: $create_interval");
		header("X-Rate-Limit-Limit: $create_limit");
		$remaining = ($create_limit - $recent >= 0) ? $create_limit - $recent : 0;
		header("X-Rate-Limit-Remaining: ".$remaining);
		header("X-Rate-Limit-Reset: ".($create_interval - (time() - strtotime($data[0]))));
		
		if($remaining == 0) {
			
			// This user is rate limited
			
			header("X-Rate-Limit-Wait: ".((time() - strtotime($data[0]))));
			
			// Check bad actors
			
			$stmt = $pdo->prepare('SELECT `count` FROM `abuser_log` WHERE `ip` = :ip');
			$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
			$data = $stmt->fetch();
			if(isset($data['count'])) {
				if($data['count'] == 25) {
					http_response_code(403);
					
					// Log one more to end the cycle
					
					$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
					$statement->execute(array(
						"ip" => $_SERVER['REMOTE_ADDR'],
						"timestamp" => date("Y-m-d H:i:s"),
						"count" => 1,
						"timestamp2" => date("Y-m-d H:i:s"),
					));
					exit;
				}
				if($data['count'] > 25) {
					http_response_code(403);
					exit;
				}
			}
			
			// Log bad actors
			
			$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
			$statement->execute(array(
				"ip" => $_SERVER['REMOTE_ADDR'],
				"timestamp" => date("Y-m-d H:i:s"),
				"count" => 1,
				"timestamp2" => date("Y-m-d H:i:s"),
			));
			
			http_response_code(429);
			exit;
		}
	}
	
	// ...proceed
	
	$key = isset($_REQUEST['key']) ? $_REQUEST['key'] : null;
	$val = isset($_REQUEST['val']) ? $_REQUEST['val'] : null;
	
	// stuff too big?
	
	if(strlen($key) > 255) {
		respond("HTTP/1.1 413 Request Entity Too Large\nYour key is more than 255 characters and your request failed.");
		exit;
	}
	
	if(strlen($val) > 255) {
		respond("HTTP/1.1 413 Request Entity Too Large\nYour value is more than 255 characters and your request failed.");
		exit;
	}
	
	// ...go on
	
	if(is_array($val)) {
		$val = json_encode($val);
	}
	
	if($key !== null && $val !== null) {
		$statement = $pdo->prepare("INSERT INTO `data` (`key`, `val`, `created`, `modified`) VALUES (:key, :val, :created, :modified) ON DUPLICATE KEY UPDATE `val` = :val_new, `modified` = :modified_new");
		$statement->execute(array(
			"key" => $key,
			"val" => $val,
			"created" => date("Y-m-d H:i:s"),
			"modified" => date("Y-m-d H:i:s"),
			"val_new" => $val,
			"modified_new" => date("Y-m-d H:i:s"),
		));
		
		$statement = $pdo->prepare("INSERT INTO `log` (`key`, `val`, `ip`, `timestamp`) VALUES (:key, :val, :ip, :timestamp)");
		$statement->execute(array(
			"key" => $key,
			"val" => $val,
			"ip" => $_SERVER['REMOTE_ADDR'],
			"timestamp" => date("Y-m-d H:i:s"),
		));
		
		http_response_code(201);
		
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['val'] = $val;
			$json['result'] = '201 Created';
		}
		
		respond($key.'='.$val, @$json);
		exit;
	}
}

// Display created

if(isset($_REQUEST['key']) && !isset($_REQUEST['val']) && isset($_REQUEST['created'])) {
	
	// Rate limit check
	
	$stmt = $pdo->prepare('SELECT timestamp FROM `read_log` WHERE ip = :ip AND timestamp > DATE_SUB(NOW(), INTERVAL '.$read_interval.' SECOND) ORDER BY timestamp DESC');
	$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
	$data = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
	
	// were there previous requests
	if(count($data) > 0) {
		$recent = count($data);
		header("X-Rate-Limit-Interval: $read_interval");
		header("X-Rate-Limit-Limit: $read_limit");
		$remaining = ($read_limit - $recent >= 0) ? $read_limit - $recent : 0;
		header("X-Rate-Limit-Remaining: ".$remaining);
		header("X-Rate-Limit-Reset: ".($read_interval - (time() - strtotime($data[0]))));
		
		if($remaining == 0) {
			
			// This user is rate limited
			
			header("X-Rate-Limit-Wait: ".((time() - strtotime($data[0]))));
			
			// Check bad actors
			
			$stmt = $pdo->prepare('SELECT `count` FROM `abuser_log` WHERE `ip` = :ip');
			$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
			$data = $stmt->fetch();
			if(isset($data['count'])) {
				if($data['count'] == 25) {
					http_response_code(403);
					
					// Log one more to end the cycle
					
					$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
					$statement->execute(array(
						"ip" => $_SERVER['REMOTE_ADDR'],
						"timestamp" => date("Y-m-d H:i:s"),
						"count" => 1,
						"timestamp2" => date("Y-m-d H:i:s"),
					));
					exit;
				}
				if($data['count'] > 25) {
					http_response_code(403);
					exit;
				}
			}
			
			// Log bad actors
			
			$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
			$statement->execute(array(
				"ip" => $_SERVER['REMOTE_ADDR'],
				"timestamp" => date("Y-m-d H:i:s"),
				"count" => 1,
				"timestamp2" => date("Y-m-d H:i:s"),
			));
			
			http_response_code(429);
			exit;
		}
	}
	
	// ...proceed
	
	$key = isset($_REQUEST['key']) ? $_REQUEST['key'] : null;
	
	// Log the read action
	
	$statement = $pdo->prepare("INSERT INTO `read_log` (`key`, `ip`, `timestamp`) VALUES (:key, :ip, :timestamp)");
	$statement->execute(array(
		"key" => $key,
		"ip" => $_SERVER['REMOTE_ADDR'],
		"timestamp" => date("Y-m-d H:i:s"),
	));
	
	// ...proceed
	
	$stmt = $pdo->prepare('SELECT `created` FROM `data` WHERE `key` = :key');
	$stmt->execute(['key' => $key]);
	$data = $stmt->fetch();
	if(isset($data['created'])) {
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['created'] = strtotime($data['created']);
		}
		respond(strtotime($data['created']), @$json);
	}
	else {
		http_response_code(404);
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['result'] = '404 Not Found';
		}
		respond('HTTP/1.1 404 Not Found', @$json);
		exit;
	}
}

// Display modified

if(isset($_REQUEST['key']) && !isset($_REQUEST['val']) && isset($_REQUEST['modified'])) {
	
	// Rate limit check
	
	$stmt = $pdo->prepare('SELECT timestamp FROM `read_log` WHERE ip = :ip AND timestamp > DATE_SUB(NOW(), INTERVAL '.$read_interval.' SECOND) ORDER BY timestamp DESC');
	$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
	$data = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
	
	// were there previous requests
	if(count($data) > 0) {
		$recent = count($data);
		header("X-Rate-Limit-Interval: $read_interval");
		header("X-Rate-Limit-Limit: $read_limit");
		$remaining = ($read_limit - $recent >= 0) ? $read_limit - $recent : 0;
		header("X-Rate-Limit-Remaining: ".$remaining);
		header("X-Rate-Limit-Reset: ".($read_interval - (time() - strtotime($data[0]))));
		
		if($remaining == 0) {
			
			// This user is rate limited
			
			header("X-Rate-Limit-Wait: ".((time() - strtotime($data[0]))));
			
			// Check bad actors
			
			$stmt = $pdo->prepare('SELECT `count` FROM `abuser_log` WHERE `ip` = :ip');
			$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
			$data = $stmt->fetch();
			if(isset($data['count'])) {
				if($data['count'] == 25) {
					http_response_code(403);
					
					// Log one more to end the cycle
					
					$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
					$statement->execute(array(
						"ip" => $_SERVER['REMOTE_ADDR'],
						"timestamp" => date("Y-m-d H:i:s"),
						"count" => 1,
						"timestamp2" => date("Y-m-d H:i:s"),
					));
					exit;
				}
				if($data['count'] > 25) {
					http_response_code(403);
					exit;
				}
			}
			
			// Log bad actors
			
			$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
			$statement->execute(array(
				"ip" => $_SERVER['REMOTE_ADDR'],
				"timestamp" => date("Y-m-d H:i:s"),
				"count" => 1,
				"timestamp2" => date("Y-m-d H:i:s"),
			));
			
			http_response_code(429);
			exit;
		}
	}
	
	// ...proceed
	
	$key = isset($_REQUEST['key']) ? $_REQUEST['key'] : null;
	
	// Log the read action
	
	$statement = $pdo->prepare("INSERT INTO `read_log` (`key`, `ip`, `timestamp`) VALUES (:key, :ip, :timestamp)");
	$statement->execute(array(
		"key" => $key,
		"ip" => $_SERVER['REMOTE_ADDR'],
		"timestamp" => date("Y-m-d H:i:s"),
	));
	
	// ...proceed
	
	$stmt = $pdo->prepare('SELECT `modified` FROM `data` WHERE `key` = :key');
	$stmt->execute(['key' => $key]);
	$data = $stmt->fetch();
	if(isset($data['modified'])) {
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['modified'] = strtotime($data['modified']);
		}
		respond(strtotime($data['modified']), @$json);
	}
	else {
		http_response_code(404);
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['result'] = '404 Not Found';
		}
		respond('HTTP/1.1 404 Not Found', @$json);
		exit;
	}
}

/*
// Display history

if(isset($_REQUEST['key']) && !isset($_REQUEST['val']) && isset($_REQUEST['history'])) {
	
	$key = isset($_REQUEST['key']) ? $_REQUEST['key'] : null;
	
	$stmt = $pdo->prepare('SELECT `modified` FROM `data` WHERE `key` = :key');
	$stmt->execute(['key' => $key]);
	$data = $stmt->fetch();
	if(isset($data['modified'])) {
		respond(strtotime($data['modified']));
	}
	else {
		http_response_code(201);
		exit;
	}
}
*/

// Display value for key

if(isset($_REQUEST['key']) && !isset($_REQUEST['val'])) {
	
	// Rate limit check
	
	$stmt = $pdo->prepare('SELECT timestamp FROM `read_log` WHERE ip = :ip AND timestamp > DATE_SUB(NOW(), INTERVAL '.$read_interval.' SECOND) ORDER BY timestamp DESC');
	$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
	$data = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
	
	// were there previous requests
	if(count($data) > 0) {
		$recent = count($data);
		header("X-Rate-Limit-Interval: $read_interval");
		header("X-Rate-Limit-Limit: $read_limit");
		$remaining = ($read_limit - $recent >= 0) ? $read_limit - $recent : 0;
		header("X-Rate-Limit-Remaining: ".$remaining);
		header("X-Rate-Limit-Reset: ".($read_interval - (time() - strtotime($data[0]))));
		
		if($remaining == 0) {
			
			// This user is rate limited!
			
			header("X-Rate-Limit-Wait: ".((time() - strtotime($data[0]))));
			
			// Check bad actors
			
			$stmt = $pdo->prepare('SELECT `count` FROM `abuser_log` WHERE `ip` = :ip');
			$stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
			$data = $stmt->fetch();
			if(isset($data['count'])) {
				if($data['count'] == 25) {
					http_response_code(403);
					
					// Log one more to end the cycle
					
					$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
					$statement->execute(array(
						"ip" => $_SERVER['REMOTE_ADDR'],
						"timestamp" => date("Y-m-d H:i:s"),
						"count" => 1,
						"timestamp2" => date("Y-m-d H:i:s"),
					));
					exit;
				}
				if($data['count'] > 25) {
					http_response_code(403);
					exit;
				}
			}
			
			// Log bad actors
			
			$statement = $pdo->prepare("INSERT INTO `abuser_log` (`ip`, `timestamp`, `count`) VALUES (:ip, :timestamp, :count) ON DUPLICATE KEY UPDATE `timestamp` = :timestamp2, `count` = `count` + 1;");
			$statement->execute(array(
				"ip" => $_SERVER['REMOTE_ADDR'],
				"timestamp" => date("Y-m-d H:i:s"),
				"count" => 1,
				"timestamp2" => date("Y-m-d H:i:s"),
			));
			
			http_response_code(429);
			exit;
		}
	}
	
	// ...proceed
	
	$key = isset($_REQUEST['key']) ? $_REQUEST['key'] : null;
	
	// Log the read action
	
	$statement = $pdo->prepare("INSERT INTO `read_log` (`key`, `ip`, `timestamp`) VALUES (:key, :ip, :timestamp)");
	$statement->execute(array(
		"key" => $key,
		"ip" => $_SERVER['REMOTE_ADDR'],
		"timestamp" => date("Y-m-d H:i:s"),
	));
	
	// ...proceed
		
	$stmt = $pdo->prepare('SELECT `val` FROM `data` WHERE `key` = :key');
	$stmt->execute(['key' => $key]);
	$data = $stmt->fetch();
	if(isset($data['val'])) {
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['val'] = $data['val'];
		}
		respond($data['val'], @$json);
	}
	else {
		http_response_code(404);
		if(@is_array($json)) {
			$json['key'] = $key;
			$json['result'] = '404 Not Found';
		}
		respond('HTTP/1.1 404 Not Found', @$json);
		exit;
	}
}


// See if $_SERVER['REQUEST_URI'] exists and if so serve it up

if($_SERVER['REQUEST_URI'] !== '/') {
	$key = $_SERVER['REQUEST_URI'];
	$key = substr($key, 1);
	$stmt = $pdo->prepare('SELECT `val` FROM `data` WHERE `key` = :key');
	$stmt->execute(['key' => $key]);
	$data = $stmt->fetch();
	if(isset($data['val'])) {
		respond($data['val']);
	}
	else {
		http_response_code(404);
		respond('HTTP/1.1 404 Not Found');
		
	}
}

/// If we've made it here, we have nothing to do, so we'll just show the landing page

?><!DOCTYPE html>
<html lang="en">
<head>

<title>Volatile</title>

<meta charset="utf-8">
<meta property="og:title" content="Volatile, a free key-value pair API">
<meta property="og:url" content="https://volatile.wtf/">
<meta property="og:image" content="https://volatile.wtf/meta/img/volatile.png">
<meta property="og:description" content="Volatile is a free key-value pair API that everyone can use. No tokens, just store and retrieve data.">
<meta name="author" content="Neatnik LLC">
<meta name="viewport" content="width=device-width">
</head>

<body>

<header>

<div class="logotype">
<a href="/">Volatile <i class="fas fa-bomb"></i></a>
</div>

</header>

<main>

<h1>Volatile is a free key-value pair API that everyone can use.</h1>

<p>Pick a key, add a value. What if that key already exists? Congrats, you’ve just updated its value. Uh, didn’t that key belong to someone else? No, because that’s not how things work here. No tokens, no ownership&mdash;just data. This is Volatile. It’s fast and it’s flexible. Use it for anything. Use it for good.</p>

<h2>Why?</h2>

<p>Sometimes you just need to put something somewhere and then fetch it later. And sometimes you need to change it without asking for anyone’s permission or keeping track of a token. Volatile is a database that anyone can edit. On the internet. That makes it both super convenient and incredibly...volatile.</p>

<h2>API</h2>

<div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(20em, 1fr)); justify-items: stretch; grid-gap: 3rem; margin-bottom: .5em;">

<div class="grid-item">
<h3>Create a key-value pair <span class="action write">write</span></h3>
<table class="method">
<tr>
<td>Usage</td>
<td>
POST key=<span class="key">key</span>&val=<span class="val">val</span><br>
GET /?key=<span class="key">key</span>&val=<span class="val">val</span>	
</td>
</tr>
<tr>
<td>Example</td>
<td><a href="https://volatile.wtf/?key=foo&val=bar">https://volatile.wtf/?key=<span class="key">foo</span>&val=<span class="val">bar</span></a></td>
</tr>
<tr>
<td>Response</td>
<td class="response">
<span class="line-number">1</span> HTTP/1.1 201 Created<br>
<span class="line-number">2</span> <span class="key">key</span>=<span class="val">val</span>
</td>
</tr>
</table>
</div>

<div class="grid-item">
<h3>Get the value for a key <span class="action read">read</span></h3>
<table class="method">
<tr>
<td>Usage</td>
<td>
POST key=<span class="key">key</span>
<br>
GET /?key=<span class="key">key</span>
</td>
</tr>
<tr>
<td>Example</td>
<td><a href="https://volatile.wtf/?key=foo">https://volatile.wtf/?key=<span class="key">foo</span></a></td>
</tr>
<tr>
<td>Response</td>
<td class="response">
<span class="line-number">1</span> HTTP/1.1 200 OK<br>
<span class="line-number">2</span> <span class="val">val</span>
</td>
</tr>
</table>
</div>

<div class="grid-item">
<h3>Get a key’s creation date <span class="action read">read</span></h3>
<table class="method">
<tr>
<td>Usage</td>
<td>
POST key=<span class="key">key</span>&created<br>
GET /?key=<span class="key">key</span>&created
</td>
</tr>
<tr>
<td>Example</td>
<td><a href="https://volatile.wtf/?key=foo&created">https://volatile.wtf/?key=<span class="key">foo</span>&created</a></td>
</tr>
<tr>
<td>Response</td>
<td class="response">
<span class="line-number">1</span> HTTP/1.1 200 OK<br>
<span class="line-number">2</span> <span class="other">Unix timestamp</span>
</td>
</tr>
</table>
</div>

<div class="grid-item">
<h3>Get a key’s modification date <span class="action read">read</span></h3>
<table class="method">
<tr>
<td>Usage</td>
<td>
POST key=<span class="key">key</span>&modified<br>
GET /?key=<span class="key">key</span>&modified
</td>
</tr>
<tr>
<td>Example</td>
<td><a href="https://volatile.wtf/?key=foo&modified">https://volatile.wtf/?key=<span class="key">foo</span>&modified</a></td>
</tr>
<tr>
<td>Response</td>
<td class="response">
<span class="line-number">1</span> HTTP/1.1 200 OK<br>
<span class="line-number">2</span> <span class="other">Unix timestamp</span>
</td>
</tr>
</table>
</div>

</div>

<h3>JSON</h3>

<p>You can send your request in JSON if you’d like. If you do, you’ll get some JSON back in return.</p>

<p>Sample request:</p>

<code>curl -d '{"key":"foo", "val":"bar"}' -H "Content-Type: application/json" -X POST https://volatile.wtf</code>

<p>Sample response:</p>

<pre>
{
    "key": "foo",
    "val": "bar",
    "result": "201 Created"
}
</pre>

<h3>Character Encoding</h3>

<p>Both <span class="key">key</span> and <span class="val">val</span> are stored as UTF-8 encoded characters. Send whatever you want, but that’s how things are stored.</p>

<h3>Character Limits</h3>

<p>Both <span class="key">key</span> and <span class="val">val</span> cannot exceed 255 characters. If you submit a request where either entity exceeds that limit, your request will fail. You’ll receive an <code>HTTP 413 Request Entity Too Large</code> response along with a plain text message explaining the failure.</p>

<h3>HTTP Methods</h3>

<p>You can use POST or GET as you see fit. If your request has both a <span class="key">key</span> <em>and</em> a <span class="val">val</span>, the <span class="val">val</span> will be stored for that <span class="key">key</span>. If you send a <span class="key">key</span> alone, then you’ll get the key’s value in response. I don’t really care which method you use or why. Enjoy the flexibility. It’s none of my business.</p>

<h3>Rate Limiting</h3>

<p>Rate limits are enforced, and are tied to the IP address making the request.</p>

<ul>
<li><strong class="write">Write actions</strong>: 100 requests every 15 minutes</li>
<li><strong class="read">Read actions</strong>: 200 requests every 15 minutes</li>
</ul>

<p>For any request where rate limiting applies, these headers will be sent in your response:</p>
<ol>
<li><code>X-Rate-Limit-Interval</code>, the interval for that type of request (in seconds)</li> 
<li><code>X-Rate-Limit-Limit</code>, the maximum number of requests permitted during the interval</li>
<li><code>X-Rate-Limit-Remaining</code>, the number of requests that are available to you</li>
<li><code>X-Rate-Limit-Reset</code>, the number of seconds until the interval resets</li>
</ol>

<p>When you run out of remaining requests, you’ll receive an <code>HTTP 419 Too Many Requests</code> response and your requests will be ignored. You’ll also receive the <code>X-Rate-Limit-Wait</code> header that tells you the number of seconds until you can make another successful request. Please wait that amount of time before trying again. If you continue to try to make requests before they are available, you’re a jerk.</p>

<h3>Retrieval Shortcut</h3>

<p>You can use this fun shortcut to access the value of any key: <strong>https://volatile.wtf/<span class="key">key</span></strong>. If the key exists, you’ll get a response with the value. If it doesn’t exist, you get <code>HTTP 404 Not Found</code> but I’m sure you’ll be able to pick up the pieces and move on with your life.</p>

<aside style="margin-top: 2em; text-align: right; font-size: 80%;"><em>API documentation last updated on 2019-11-28 to reflect a new rate limit on read actions</em></aside>

<h2>FAQs</h2>

<h3>Your service doesn’t technically conform with <a href="https://tools.ietf.org/html/rfc2616#section-9.1.1">RFC 2616</a>; how can you live with yourself?</h3>
<p>Some people are using this in more constrained technical contexts where they can GET but not POST. In accommodating those edge cases I understand that I’m not following the spec precisely, but I don’t really care. See also: this service’s name.</p>

<h3>Is my information safe?</h3>
<p>Probably not, but that depends on your definition of “safe”. Anything you store here could be accessed or overwritten by anyone else at any time.</p>

<h3>Why would anyone want to use this?</h3>
<p>I can't answer for anyone else, but I can tell you why I use it. It’s fast and it’s simple. It’s great for times when you just need to store small things and don’t want the overhead of a database. A key with <a href="https://xkcd.com/936/">sufficient entropy</a> is unlikely to be discovered.</p>

<h3>Is this secure? Can it be exploited?</h3>
<p>Yes, it’s secure. No, I don’t think it can be exploited, but people are creative.</p>

<h3>How do I know this service won’t disappear overnight?</h3>
<p>Good question—it actually did disappear overnight. Nothing lasts forever.</p>

<h2>Legal</h2>

<p>This service is provided on an as-is basis. We disclaim all warranties. Everyone reserves the right to do everything because that’s the entire point of the service. Change is constant. Death is part of life. Here be dragons. Abandon all hope.</p>

</main>

</body>
</html>
