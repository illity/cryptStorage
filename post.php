<?php
	$url =  "{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
	$url_components = parse_url($url);
	parse_str($url_components['query'], $params);
	if (isset($params['password'])) {
		$password = $params['password'];
		// $hashed_password =  password_hash($password, PASSWORD_DEFAULT);
		$hashed_password = file_get_contents("./encryptedPass.md");
	} else {return;}
	if(!password_verify($password, $hashed_password)) {return;}

	$action = $params['action'];
	$ciphering_value = "AES-128-CTR";  
	$encryption_key = $password;
	$VI = 3921831234545455;
	function decrypt($str) {
		global $ciphering_value, $encryption_key, $VI;
		return openssl_decrypt($str, $ciphering_value, $encryption_key, 0, $VI);
	}
	
	if ($action == "append") {
		$original_string = $params['input']; 
		$encryption_value = openssl_encrypt($original_string, $ciphering_value, $encryption_key, 0, $VI); 
		file_put_contents('data.data', $encryption_value.PHP_EOL, FILE_APPEND);
		echo $encryption_value;
	}
	if ($action == "read") {
		$data_content = file_get_contents("./data.data");
		$encrypted_data = explode(PHP_EOL,$data_content);
		$decrypted_data = array_map('decrypt', $encrypted_data);
		echo json_encode($decrypted_data);
	}
?>