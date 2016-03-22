<?php
session_start();
require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';
\Slim\Slim::registerAutoloader();
$app = new \Slim\Slim();
// User id from db - Global Variable
$user_id = NULL;
/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();
    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();
        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}


$authenticate = function ($app) {
    return function () use ($app) {
        if (!isset($_SESSION['user'])) {
			$response["error"] = true;
			$response["message"] = "Login Required";
			// echo json response
			echoRespnse(201, $response);
			exit;
        }
    };
};

$app->hook('slim.before', function() use ($app) {
    if (isset($_SESSION['user'])) {
        $user = $_SESSION['user'];
        $app->view()->appendData(array('session'=>$user));
    } 

});


function checkloginuserisadmin(){
	if(isset($_SESSION)){
		if( $_SESSION['user']['roleid'] != 1){
			$response["error"] = true;
			$response["message"] = "You are not autorized to access this";
			// echo json response
			echoRespnse(201, $response);
			exit;
		}
	}else{
		$response["error"] = true;
		$response["message"] = "Login Required";
		// echo json response
		echoRespnse(201, $response);
		exit;
	}
}


function checkuserlogin(){
	if (isset($_SESSION['user'])) {
		$response["error"] = true;
		$response["message"] = "You are already login";
		// echo json response
		echoRespnse(201, $response);
		exit;
	}

}
/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
*/

$app->post('/login', function() use ($app) {
	        checkuserlogin();
            // check for required params
            verifyRequiredParams(array('email', 'password'));
            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
			
            $response = array();
            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);
				
                if ($user != NULL) {
				    $response["error"] = false;
                    $response['name'] = $user['user_name'];
                    $response['email'] = $user['user_email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['created'] = $user['created'];
                    $response['roleid'] = $user['role_id'];
                    $response['rolename'] = $user['rolename'];
                    $response['id'] = $user['id'];
					$_SESSION['user'] = $response;
					//$app->view()->setData(array('title' => $title, 'descr' => $descr));
					//$app->redirect('list');					
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }
            echoRespnse(200, $response);
        });
		
/*
* ------------------------ Logout ------------------------
*/
$app->get('/logout', function () use ($app) {
	$db = new DbHandler();
	$id = $_SESSION['user']['id'];
	$type = 'logout';
	$db->updateusersesion($id,$type);
	session_destroy();
	$app->view()->setData(array('session' => false));
	$response['error'] = false;
	$response['message'] = 'Successfully Logout';
	// fetching all user tasks 
	echoRespnse(200, $response);
});
 
 
$app->post('/changepassword', function() use($app){
			
            $response = array();
			if (isset($_SESSION['user'])) {
				verifyRequiredParams(array('current_password','new_password'));
				$email = $_SESSION['user']['email'];
				$current_password = $app->request->post('current_password');
				$new_password = $app->request->post('new_password');
				$data = array('current_password'=>$current_password,'new_password'=>$new_password,'email'=>$email);
			}else{
				verifyRequiredParams(array('current_password','new_password','email'));
				$current_password = $app->request->post('current_password');
				$new_password = $app->request->post('new_password');
				$data = array('current_password'=>$current_password,'new_password'=>$new_password,'email'=>$email);
			}
            $db = new DbHandler();
            // fetching all user tasks  
            $res = $db->changepassword($data);
			if ($res == SUCCESS) {
                $response["error"] = false;
                $response["message"] = "Password Changed Successfully,Please login again ";
            } else if ($res == FAIL) {
                $response["error"] = true;
                $response["message"] = "There is some error , Please try again";
            }else if($res == USER_NOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Email is not exist";
			}else if($res == CURRENT_PASSWORD_NOTMATCHED){
                $response["error"] = true;
                $response["message"] = "Current password not correct,please try again.";
			}
            // echo json response
            echoRespnse(201, $response);
        });
 
 
 
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
*/
 
$app->post('/forgetpassword', function() use($app){
            verifyRequiredParams(array('user_email'));
            $response = array();
			$user_email = $app->request->post('user_email');
			$data = array('user_email'=>$user_email);
            $db = new DbHandler();
            // fetching all user tasks  
            $res = $db->forgotpassword($data);
			if ($res == MAIL_SENT_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Mail has successfully sent to your email, Please check to reset";
            } else if ($res == MAIL_SENT_FAIL) {
                $response["error"] = true;
                $response["message"] = "error: MAIL SENT FAILURE";
            } else if ($res == EMAIL_ISNOT_VALID) {
                $response["error"] = true;
                $response["message"] = "Sorry, user not exist";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->get('/resetpassword', function() use($app){
		verifyRequiredParams(array('email'));
		$response = array();
		$user_email = $app->request->get('email');
		$data = array('user_email'=>$user_email);
		$db = new DbHandler();
		// fetching all user tasks  
		$res = $db->resetPassword($data);
		if ($res == PASSWORD_CHANGED_SUCCESSFULLY) {
			$response["error"] = false;
			$response["message"] = "Mail has successfully sent to your email, Please check your password ";
		} else if ($res == PASSWORD_CHANGED_FAILED) {
			$response["error"] = true;
			$response["message"] = "error: MAIL SENT FAILURE";
		} else if ($res == EMAIL_ISNOT_VALID) {
			$response["error"] = true;
			$response["message"] = "Sorry, this email already existed";
		}
		// echo json response
		echoRespnse(201, $response);
	});

 
$app->post('/register', function() use ($app) {
		checkuserlogin();
		// check for required params
		verifyRequiredParams(array('name', 'email', 'password','dob'));
		$response = array();
		// reading post params
		$name = $app->request->post('name');
		$email = $app->request->post('email');
		$password = $app->request->post('password');
		$dob      = $app->request->post('dob');
		
		$data = array(
					  'name'=>$name,
					  'email'=>$email,
					  'password'=>$password,
					  'dob'=>$dob,
					  );
		validateEmail($email);
		$db = new DbHandler();
		$res = $db->createUser($data);
		if ($res == USER_CREATED_SUCCESSFULLY) {
			$response["error"] = false;
			$response["message"] = "You are successfully registered";
		} else if ($res == USER_CREATE_FAILED) {
			$response["error"] = true;
			$response["message"] = "Oops! An error occurred while registereing";
		} else if ($res == USER_ALREADY_EXISTED) {
			$response["error"] = true;
			$response["message"] = "Sorry, this email already existed";
		} else if($res == DATE_NOT_VALID){
			$response["error"] = true;
			$response["message"] = "Sorry, DOB is not valid";
		}
		// echo json response
		echoRespnse(201, $response);
	});
		
		
$app->post('/edituser',$authenticate($app), function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id = $app->request->post('id');
            $user_name   = $app->request->post('user_name');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'user_name'=>$user_name
						  );
			
			
            $res = $db->userAction($data,'edit');
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while Editing";
            }else if($res == SYSTEM_ERROR){
                $response["error"] = true;
                $response["message"] = "Oops! update is ignored";
			}
            // echo json response
            echoRespnse(201, $response);
        });
	 	
$app->get('/deleteuser',$authenticate($app), function() use ($app) {
            // check for required params
            $response = array();
            //reading post params
            $id   = $_SESSION['user']['id'];
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->userAction($data,'delete');
            if ($res == USER_DELETED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == USER_DELETED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}else if($res == USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! You are not right user";
			}
            // echo json response
            echoRespnse(201, $response);
        });
		
		

/*
  * Listing all tasks of particual user
  * method GET
  * url /tasks          
*/
$app->get('/use',$authenticate($app), function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallusers();
            $response["error"] = false;
            $response["users"] = array();
            // looping through result and preparing tasks array
            while ($users = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      = $users["id"];
                $tmp["user_email"]   = $users["user_email"];
                $tmp["user_name"]    = $users["user_name"];
                $tmp["version"]      = $users["version"];
                $tmp["version_date"] = $users["version_date"];
                $tmp["active"]       = $users["flag_user_active"];
                array_push($response["users"], $tmp);
            }
            echoRespnse(200, $response);
		});
		
		
		
		
		
/**
 * Qr Image
 * url - /qrimage
 * method - POST
 * params - authkey
 */
$app->post('/admin/qrimage',$authenticate($app),function() use ($app){
			// reading post params
			$id = $app->request()->post('pharmaid');
			$role_id = $app->request()->post('role_id');
			$startdate = $app->request()->post('startdate');
			$enddate = $app->request()->post('enddate');
			$response = array();
			$db = new DbHandler();
			$response["error"] = false;
			$qrimage = $db->qrgenerator($id,$role_id,$startdate,$enddate);
			$response["qrimage"] = $qrimage['pharmacist'];
			echoRespnse(200, $response);
		});

		
/**
 * Add user by admin 
 * method POST
 * url v1/admin/adduser          
*/

$app->post('/admin/adduser',$authenticate($app),function() use ($app){
	        checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password','role_id'));
            $response = array();
            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $dob = $app->request->post('dob');
            $role_id = $app->request->post('role_id');
			$data = array( 
						  'name'=>$name,
						  'email'=>$email,
						  'password'=>$password,
						  'roleid'=>$role_id,
						  'dob' => $dob
						  );
            validateEmail($email);
            $db = new DbHandler();
            $res = $db->createUser($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/edituser', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            // reading post params
			$id = $app->request->post('id');
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $roleid = $app->request->post('roleid');
            $dob = $app->request->post('dob');
			$data = array('id'=>$id,
						  'name'=>$name,
						  'email'=>$email,
						  'roleid'=>$roleid,
						  'dob' => $dob
						  );
            $db = new DbHandler();
            $res = $db->updateUser($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deleteuser',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteuser($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response
            echoRespnse(201, $response);
        });

$app->get('/admin/listusers',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->listusers();
            $response["error"] = false;
            $response["users"] = array();
            // looping through result and preparing tasks array
            while ($users = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      = $users["userid"];
                $tmp["user_email"]   = $users["user_email"];
                $tmp["user_name"]    = $users["user_name"];
                $tmp["create_date"]  = $users["user_create_date"];
				$tmp["dob"]          = $users["user_dob"];
				if(!empty($users["role_name"])){
					$role = $users["role_name"];
				}else{
				    $role = '';
				}
				$tmp["role"] = $users["role_name"];
                array_push($response["users"], $tmp);
            }
            echoRespnse(200, $response);
		});

		
/**
 * Add Pharmacist by admin 
 * method POST
 * url v1/admin/addpharmacist 
 * prameter for post or get   parameter  URL,authenticate ,function         
 */
$app->post('/admin/addpharmacy',$authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array( 'name', 'phone', 'address1','zip','town','email'));
            $response = array();
            // reading post params address1,address2,zip,town,latitude,longitude,phone,url,status
			$name   = $app->request->post('name');
            $address1 = $app->request->post('address1');
            $address2 = $app->request->post('address2');
            $zip = $app->request->post('zip');
            $town = $app->request->post('town');
            $latitude = $app->request->post('latitude');
            $longitude = $app->request->post('longitude');
            $phone = $app->request->post('phone');
			$url   = $app->request->post('url');
			$email   = $app->request->post('email');
			$groupid   = $app->request->post('groupid');
			$pharmacistname   = $app->request->post('pharmacistname');
			$version   = $app->request->post('version');
			$versionid   = $app->request->post('versionid');
			$pharmacy_active   = $app->request->post('pharmacy_active');
			
			
			$data = array( 
						  'name' => $name,
						  'address1'=>$address1,
						  'address2'=>$address2,
						  'zip'=>$zip,
						  'town'=>$town,
						  'latitude'=>$latitude,
						  'longitude'=>$longitude,
						  'phone' => $phone,
						  'url' => $url,
						  'email' => $email,
						  'groupid'=>$groupid,
						  'pharmacistname' => $pharmacistname,
						  'version' => $version,
						  'versionid' => $versionid,
						  'pharmacy_active'=>$pharmacy_active
						  
						  );
            //validateEmail($email);
            $db = new DbHandler();
            $res = $db->createPharma($data);
            if ($res == PHARMA_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully added pharma";
            } else if ($res == PHARMA_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == PHARMA_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
	
	
$app->get('/admin/pharmacy',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallpharmacy();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	   = $pharmacy["id"];
				$tmp["id_pharmacy"]        = $pharmacy["id_pharmacy"];
				$tmp["user_name"]    	   = $pharmacy["pharmacy_name"];
				$tmp["id_group"]   	   = $pharmacy["id_group"];
                $tmp["pharmacy_addr1"]     = $pharmacy["pharmacy_addr1"];
                $tmp["pharmacy_addr2"]     = $pharmacy["pharmacy_addr2"];
                $tmp["pharmacy_zip"]       = $pharmacy["pharmacy_zip"];
                $tmp["pharmacy_city"] 	   = $pharmacy["pharmacy_city"];
                $tmp["pharmacy_latitude"]  = $pharmacy["pharmacy_latitude"];
				$tmp["user_email"]   	   = $pharmacy["pharmacy_email"];
				$tmp["pharmacy_phone"]     = $pharmacy["pharmacy_phone"];
                $tmp["pharmacist_name"]    = $pharmacy["pharmacist_name"];
				$tmp["active"]       	   = $pharmacy["pharmacy_active"];
                $tmp["version"]      	   = $pharmacy["version"];
				$tmp["id_user_version"]    = $pharmacy["id_user_version"];
                $tmp["version_date"] 	   = $pharmacy["version_date"];
                $tmp["pharmacy_longitude"] = $pharmacy["pharmacy_longitude"];
                
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response);
		});
		
$app->post('/infopharma',$authenticate($app), function() use($app){
            verifyRequiredParams(array('pharmacy_code'));
            $response = array();
			$pharmacy_code = $app->request->post('pharmacy_code');
			$data = array('pharmacy_code'=>$pharmacy_code
						  );  
            $db = new DbHandler();
            // fetching all user tasks  
            $result = $db->infopharma($data);
			
            if ($result == CODE_ERROR) {
                $response["error"] = true;
                $response["message"] = "Code has been Expired or Not exist. Contact to Administrator";
            }else{
				$response["error"] = false;
				$response["pharmacy"] = $result['pharmacy'];
            }
            echoRespnse(200, $response);  
		});
		
$app->post('/admin/editpharmacyaccess', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('pharmacy_code'));
            $response = array();
            // reading post params
			$id_pharmacy = $app->request->post('pharmacy_code');
            $id_role = $app->request->post('id_role');
            $pharmacy_code_start_date = $app->request->post('pharmacy_code_start_date');
            $pharmacy_code_end_date = $app->request->post('pharmacy_code_end_date');
			$data = array('id_pharmacy'=>$id_pharmacy,
						  'id_role'=>$id_role,
						  'pharmacy_code_start_date'=>$pharmacy_code_start_date,
						  'pharmacy_code_end_date'=>$pharmacy_code_end_date
						  );
            $db = new DbHandler();
            $res = $db->editpharmacyaccess($data);
            if ($res == PHARMACYACCESS_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == PHARMACYACCESS_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletepharmacyaccess',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
            verifyRequiredParams(array('pharmacy_code'));
            $response = array(); 
            //reading post params
            $id   = $app->request->post('pharmacy_code');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletepharmacyaccess($data);
            if ($res == PHARMA_DELETED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_DELETED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registering";
			}
            // echo json response
            echoRespnse(201, $response);
        });


		
$app->post('/admin/editpharmacy', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id', 'name'));
            $response = array();
            // reading post params
            $id = $app->request->post('id');
			$name   = $app->request->post('name');
            $address1 = $app->request->post('address1');
            $address2 = $app->request->post('address2');
            $zip = $app->request->post('zip');
            $town = $app->request->post('town');
            $latitude = $app->request->post('latitude');
            $longitude = $app->request->post('longitude');
            $phone = $app->request->post('phone');
			$url   = $app->request->post('url');
			$email   = $app->request->post('email');
			$groupid   = $app->request->post('groupid');
			$pharmacistname   = $app->request->post('pharmacistname');
			$version   = $app->request->post('version');
			$versionid   = $app->request->post('versionid');
			$pharmacy_active   = $app->request->post('pharmacy_active');
			$data = array( 
						  'id'=>$id,
						  'name' => $name,
						  'address1'=>$address1,
						  'address2'=>$address2,
						  'zip'=>$zip,
						  'town'=>$town,
						  'latitude'=>$latitude,
						  'longitude'=>$longitude,
						  'phone' => $phone,
						  'url' => $url,
						  'email' => $email,
						  'groupid'=>$groupid,
						  'pharmacistname' => $pharmacistname,
						  'version' => $version,
						  'versionid' => $versionid,
						  'pharmacy_active'=>$pharmacy_active
						  );
            $db = new DbHandler();
            $res = $db->updatepharmacy($data);
            if ($res == true) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == false) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletepharmacy',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array(); 
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletepharmacy($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
			
            // echo json response
            echoRespnse(201, $response);
        });
		
		
		
$app->post('/admin/addpharmacyday',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_pharmacy','day_start_time', 'day_end_time','idday'));
            $response = array();
            // reading post params
			$idpharmacy = $app->request->post('id_pharmacy');
			$idday = $app->request->post('idday');
            $starttime = $app->request->post('day_start_time');
            $endtime = $app->request->post('day_end_time');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
            $versiondate = $app->request->post('versiondate');
			
			$data = array(
						  'idpharmacy'=>$idpharmacy,
						  'idday'=>$idday,
						  'starttime'=>$starttime,
						  'endtime'=>$endtime,
						  'version'=>$version,
						  'iduserversion'=>$iduserversion,
						  'versiondate'=>$versiondate,
						  );
            $db = new DbHandler();
            $res = $db->addpharmacyday($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editpharmacyday',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','day_start_time','day_end_time'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
			$daystarttime = $app->request->post('day_start_time');
			$dayendtime = $app->request->post('day_end_time');
			$id_day = $app->request->post('id_day');
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version'); 
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'daystarttime'=>$daystarttime,
						  'dayendtime'=>$dayendtime,
						  'id_day'=>$id_day,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->editpharmacyday($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletepharmacyday',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletepharmacyday($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listpharmacyday',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallpharmacyday();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["pharmacy_id"]   	 = $pharmacy["id_pharmacy"];
                $tmp["day_id"]    	   	 = $pharmacy["id_day"];
                $tmp["day_start_time"]   = $pharmacy["day_start_time"];
                $tmp["day_end_time"] 	 = $pharmacy["day_end_time"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
                $tmp["flag_pharmacy_day"]= $pharmacy["flag_pharmacy_day"];
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response);
		});

$app->post('/admin/addpharmacylaboratory',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_pharmacy','laboratory_start_date', 'laboratory_end_date'));
            $response = array();
            // reading post params
			$id_pharmacy = $app->request->post('id_pharmacy');
			$laboratoryid = $app->request->post('laboratoryid');
            $startday = $app->request->post('laboratory_start_date');
            $endday = $app->request->post('laboratory_end_date');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
			
			$data = array(
						  'id_pharmacy'=>$id_pharmacy,
						  'laboratoryid'=>$laboratoryid,
						  'startday'=>$startday,
						  'endday'=>$endday,
						  'version'=>$version,
						  'iduserversion'=>$iduserversion
						  );
            $db = new DbHandler();
            $res = $db->addpharmacylaboratory($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editpharmacylaboratory',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','laboratory_id','laboratory_start_date','laboratory_end_date'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
			$laboratoryid   = $app->request->post('laboratory_id');
			$startday = $app->request->post('laboratory_start_date');
			$endday = $app->request->post('laboratory_end_date');
			$version = $app->request->post('version');
			$iduserversion = $app->request->post('id_user_version');
            $db   = new DbHandler();
			$data = array(
						  'id'=>$id,
						  'laboratoryid'=>$laboratoryid,
						  'startday'=>$startday,
						  'endday'=>$endday,
						  'iduserversion'=>$iduserversion,
						  'version'=>$version
						  );
			
            $res = $db->editpharmacylaboratory($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletepharmacylaboratory',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletepharmacylaboratory($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listpharmacylaboratory',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallpharmacylaboratory();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["pharmacy_id"]   	 = $pharmacy["id_pharmacy"];
                $tmp["id_laboratory"]    	   	 = $pharmacy["id_laboratory"];
                $tmp["day_start"]   = $pharmacy["laboratory_start_date"];
                $tmp["day_end"] 	 = $pharmacy["laboratory_end_date"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});
		

$app->post('/admin/addpharmacyrole',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_pharmacy','id_role','pharmacy_role_start_date', 'pharmacy_role_end_date'));
            $response = array();
            // reading post params
			$id_user = $app->request->post('id_user');
			$id_pharmacy = $app->request->post('id_pharmacy');
            $id_role = $app->request->post('id_role');
            $pharmacy_role_start_date = $app->request->post('pharmacy_role_start_date');
			$pharmacy_role_end_date = $app->request->post('pharmacy_role_end_date');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
			$email = $app->request->post('email');
			
			$data = array(
						  'id_user'=>$id_user,
						  'id_pharmacy' => $id_pharmacy,
						  'id_role'=>$id_role,
						  'pharmacy_role_start_date'=>$pharmacy_role_start_date,
						  'pharmacy_role_end_date'=>$pharmacy_role_end_date,
						  'version'=>$version,
						  'iduserversion'=>$iduserversion,
						  'email'=>$email
						  );
            $db = new DbHandler();
            $res = $db->addpharmacyrole($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Data successfully added";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editpharmacyrole',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','pharmacy_role_start_date','pharmacy_role_end_date'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
			$id_user = $app->request->post('id_user');
			$id_role = $app->request->post('id_role');
			$startday = $app->request->post('pharmacy_role_start_date');
			$endday = $app->request->post('pharmacy_role_end_date');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_user'=>$id_user,
						  'id_role'=>$id_role,
						  'endday'=>$endday,
						  'startday'=>$startday,
						  );
			
            $res = $db->editpharmacyrole($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deletepharmacyrole',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletepharmacyrole($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listpharmacyrole',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallpharmacyrole();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["pharmacy_id"]   	 = $pharmacy["id_pharmacy"];
				$tmp["id_user"]   	 = $pharmacy["id_user"];
                $tmp["id_role"]    	   	 = $pharmacy["id_role"];
                $tmp["pharmacy_role_start_date"]   = $pharmacy["pharmacy_role_start_date"];
                $tmp["pharmacy_role_end_date"] 	 = $pharmacy["pharmacy_role_end_date"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});
		
$app->get('/dayschedule',$authenticate($app), function() use($app){
			checkloginuserisadmin();
			verifyRequiredParams(array('idpharma'));
			$idpharma  = $app->request->get('idpharma');  
            global $user_id;
            $response = array();
            $db = new DbHandler();
			$data = array('idpharma'=> $idpharma);
            // fetching all user tasks
            $result = $db->dayschedule($data);
            $response["error"] = false;
			$response["pharmacy"] = array();

		    $tmp = array();

            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
				$tmp[$pharmacy['id_day']][]= array($pharmacy['day_start_time'].",".$pharmacy['day_end_time']);
            }
			$response["pharmacy-working-schedule"] = $tmp;
            echoRespnse(200, $response); 
		});
		
$app->post('/admin/addproduct',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_product','id_laboratory', 'product_name','product_description','product_indication','product_posology','id_typeprice'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $id_laboratory = $app->request->post('id_laboratory');
            $id_range = $app->request->post('id_range');
			$product_name = $app->request->post('product_name');
            $product_description = $app->request->post('product_description');
			$product_indication = $app->request->post('product_indication');
            $product_posology = $app->request->post('product_posology');
			$id_typeprice = $app->request->post('id_typeprice');
			$id_unit = $app->request->post('id_unit');
			
			$data = array(
						  'id_product'=>$id_product,
						  'id_laboratory'=>$id_laboratory,
						  'id_range'=>$id_range,
						  'product_name'=>$product_name,
						  'product_description'=>$product_description,
						  'product_indication'=>$product_indication,
						  'product_posology'=>$product_posology,
						  'id_typeprice'=>$id_typeprice,
						  'id_unit'=>$id_unit
						  );
            $db = new DbHandler();
            $res = $db->product($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editproduct',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','id_product','id_laboratory', 'product_name','product_description','product_indication','product_posology','id_typeprice'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
            $id_product = $app->request->post('id_product');
            $id_laboratory = $app->request->post('id_laboratory');
            $id_range = $app->request->post('id_range');
			$product_name = $app->request->post('product_name');
            $product_description = $app->request->post('product_description');
			$product_indication = $app->request->post('product_indication');
            $product_posology = $app->request->post('product_posology');
			$id_typeprice = $app->request->post('id_typeprice');
			$id_unit = $app->request->post('id_unit');
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_product'=>$id_product,
						  'id_laboratory'=>$id_laboratory,
						  'id_range'=>$id_range,
						  'product_name'=>$product_name,
						  'product_description'=>$product_description,
						  'product_indication'=>$product_indication,
						  'product_posology'=>$product_posology,
						  'id_typeprice'=>$id_typeprice,
						  'id_unit'=>$id_unit,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->editproduct($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deleteproduct',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproduct($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		 
$app->get('/admin/listproduct',$authenticate($app), function() { 
			checkloginuserisadmin();
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallproduct();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["id_product"]   	 = $pharmacy["id_product"];
				$tmp["id_laboratory"]   	 = $pharmacy["id_laboratory"];
                $tmp["id_range"]    	   	 = $pharmacy["id_range"];
                $tmp["product_name"]   = $pharmacy["product_name"];
                $tmp["product_description"] 	 = $pharmacy["product_description"];
               	$tmp["product_indication"]       	 = $pharmacy["product_indication"];
				$tmp["product_posology"]  = $pharmacy["product_posology"];
                $tmp["id_typeprice"]     = $pharmacy["id_typeprice"];
				$tmp["id_unit"]    	   	 = $pharmacy["id_unit"];
                $tmp["product_active"]   = $pharmacy["product_active"];
                $tmp["version"] 	 = $pharmacy["version"];
               	$tmp["id_user_version"]       	 = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});



$app->post('/admin/addproducttag',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_product','id_tag', 'product_tag_score'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $id_tag = $app->request->post('id_tag');
            $product_tag_score = $app->request->post('product_tag_score');
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			
			$data = array(
						  'id_product'=>$id_product,
						  'id_tag'=>$id_tag,
						  'product_tag_score'=>$product_tag_score,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db->addproducttag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/editproducttag',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_product','id_tag', 'product_tag_score'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_product = $app->request->post('id_product');
            $id_tag = $app->request->post('id_tag');
            $product_tag_score = $app->request->post('product_tag_score');
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_product'=>$id_product,
						  'id_tag'=>$id_tag,
						  'product_tag_score'=>$product_tag_score,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->editproducttag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deleteproducttag',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproducttag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listproducttag',$authenticate($app), function() use ($app){ 
			checkloginuserisadmin();
			$id_product = $app->request->get('id_product');
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getproducttag($id_product);
            $response["error"] = false;
            $response["prodtag"] = array();
            // looping through result and preparing tasks array
            while ($prodtag = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $prodtag["id"];
                $tmp["id_product"]   	 = $prodtag["id_product"];
				$tmp["id_tag"]   	 	 = $prodtag["id_tag"];
                $tmp["product_tag_score"]= $prodtag["product_tag_score"];
              
                array_push($response["prodtag"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addproduct_composition',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_product','id_ingredient','version','id_user_version'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $id_ingredient = $app->request->post('id_ingredient');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
          
			
			$data = array(
						  'id_product'=>$id_product,
						  'id_ingredient'=>$id_ingredient,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db->composition($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editcomposition',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','id_product','id_ingredient','version','id_user_version'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_product = $app->request->post('id_product');
            $id_ingredient = $app->request->post('id_ingredient');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
           
			$data = array('id'=>$id,
						  'id_product'=>$id_product,
						  'id_ingredient'=>$id_ingredient,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
			$res = $db->editcomposition($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletecomposition',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletecomposition($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listproductcomposition',$authenticate($app), function() { 
			checkloginuserisadmin();
            global $user_id; 
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->productcomposition();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	= $pharmacy["id"];
                $tmp["id_product"]   	= $pharmacy["id_product"];
				$tmp["id_laboratory"]   = $pharmacy["id_ingredient"];
                $tmp["version"]   		= $pharmacy["version"];
                $tmp["id_user_version"] = $pharmacy["id_user_version"];
               	$tmp["version_date"]    = $pharmacy["version_date"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addproductform',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('form_id','form_name','form_description'));
            $response = array();
            // reading post params
			$form_id = $app->request->post('form_id');
            $form_name = $app->request->post('form_name');
			$form_description = $app->request->post('form_description');
          
			
			$data = array(
						  'form_id'=>$form_id,
						  'form_name'=>$form_name,
						  'form_description'=>$form_description
						  );
            $db = new DbHandler();
            $res = $db->addproductform($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/editproductform',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','form_id','form_name','form_description'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$form_id = $app->request->post('form_id');
            $form_name = $app->request->post('form_name');
			$form_description = $app->request->post('form_description');
			
           
			$data = array('id'=>$id,
						  'form_id'=>$form_id,
						  'form_name'=>$form_name,
						  'form_description'=>$form_description
						  );
            $db = new DbHandler();
			$res = $db->editproductform($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deleteproductform',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproductform($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listproductform',$authenticate($app), function() {
			checkloginuserisadmin();
            global $user_id; 
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->productform();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	= $pharmacy["id"];
                $tmp["form_id"]   	= $pharmacy["form_id"];
				$tmp["form_name"]   = $pharmacy["form_name"];
                $tmp["form_description"]   		= $pharmacy["form_description"];
                $tmp["form_status"] = $pharmacy["form_status"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addproductingredient',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('ingredient_id','ingredient_name'));
            $response = array();
            // reading post params
			$ingredient_id = $app->request->post('ingredient_id');
            $cosing_reference = $app->request->post('cosing_reference');
			$ingredient_name = $app->request->post('ingredient_name');
			$rating = $app->request->post('rating');
          
			
			$data = array(
						  'ingredient_id'=>$ingredient_id,
						  'cosing_reference'=>$cosing_reference,
						  'ingredient_name'=>$ingredient_name,
						  'rating'=>$rating
						  );
            $db = new DbHandler();
            $res = $db->addproductingredient($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/editproductingredient',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','ingredient_id','ingredient_name'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$ingredient_id = $app->request->post('ingredient_id');
            $cosing_reference = $app->request->post('cosing_reference');
			$ingredient_name = $app->request->post('ingredient_name');
			$rating = $app->request->post('rating');
			
           
			$data = array('id'=>$id,
						  'ingredient_id'=>$ingredient_id,
						  'cosing_reference'=>$cosing_reference,
						  'ingredient_name'=>$ingredient_name,
						  'rating'=>$rating
						  );
            $db = new DbHandler();
			$res = $db->editproductingredient($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deleteproductingredient',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproductingredient($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listproductingredient',$authenticate($app), function() { 
			checkloginuserisadmin();
            global $user_id; 
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->productingredient();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	= $pharmacy["id"];
                $tmp["ingredient_id"]   	= $pharmacy["ingredient_id"];
				$tmp["cosing_reference"]   = $pharmacy["cosing_reference"];
                $tmp["ingredient_name"]   		= $pharmacy["ingredient_name"];
                $tmp["rating"] = $pharmacy["rating"];
               	$tmp["ingredient_status"]    = $pharmacy["ingredient_status"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addproductrangeprice', $authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('range_price_id','range_price_text', 'range_price_picture'));
            $response = array();
            // reading post params
			$range_price_id = $app->request->post('range_price_id');
            $range_price_text = $app->request->post('range_price_text');
            $range_price_picture = $app->request->post('range_price_picture');
			
			
			$data = array(
						  'range_price_id'=>$range_price_id,
						  'range_price_text'=>$range_price_text, 
						  'range_price_picture'=>$range_price_picture
						  );
            $db = new DbHandler();
            $res = $db->productrangeprice($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editproductrangeprice',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id','range_price_id','range_price_text', 'range_price_picture'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$range_price_id = $app->request->post('range_price_id');
            $range_price_text = $app->request->post('range_price_text');
            $range_price_picture = $app->request->post('range_price_picture');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'range_price_id'=>$range_price_id,
						  'range_price_text'=>$range_price_text, 
						  'range_price_picture'=>$range_price_picture
						  ); 
			
            $res = $db->editproductrangeprice($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deleteproductrangeprice',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproductrangeprice($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listproductrangeprice',$authenticate($app), function() { 
			checkloginuserisadmin();
            global $user_id; 
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->productproductrangeprice();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	= $pharmacy["id"];
                $tmp["range_price_id"]   	= $pharmacy["range_price_id"];
				$tmp["range_price_text"]   = $pharmacy["range_price_text"];
                $tmp["range_price_picture"]   		= $pharmacy["range_price_picture"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addpharmacypromotion' ,$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_pharmacy','startdate','enddate'));
            $response = array();  
            // reading post params
			$pharmacy_id = $app->request->post('id_pharmacy');
            $promotion_start_date = $app->request->post('startdate');
            $promotion_end_date = $app->request->post('enddate');
			
			$data = array(
						  'pharmacy_id'=>$pharmacy_id,
						  'promotion_start_date'=>$promotion_start_date,
						  'promotion_end_date'=>$promotion_end_date
						  ); 
            $db = new DbHandler();
            $res = $db->addpharmacypromotion($data);
            if ($res == PROMOTION_SUCCESSFULLY) {
                $response["error"] = false; 
                $response["message"] = "Pharmacy promotion are successfully registered";
            } else if ($res == PROMOTION_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
			}
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editpharmacypromotion',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_promotion','startdate','enddate'));
            $response = array();
            //reading post params
			$id_promotion = $app->request->post('id_promotion');
            $promotion_start_date = $app->request->post('startdate');
            $promotion_end_date = $app->request->post('enddate');
			
            $db   = new DbHandler();  
			$data = array(
						  'id_promotion'=>$id_promotion,
						  'promotion_start_date'=>$promotion_start_date,
						  'promotion_end_date'=>$promotion_end_date
						  ); 
			
            $res = $db->editpharmacypromotion($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deletepharmacypromotion',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_promotion'));
            $response = array();
            //reading post params
            $id_promotion   = $app->request->post('id_promotion');
            $db   = new DbHandler();
			$data = array('id_promotion'=>$id_promotion);
			
			
            $res = $db->deletepharmacypromotion($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "pharmacy promotion are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while deleting";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listpharmacypromotion',$authenticate($app), function() { 
            global $user_id; 
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->listpharmacypromotion();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	= $pharmacy["id"];
                $tmp["range_price_id"]   	= $pharmacy["range_price_id"];
				$tmp["range_price_text"]   = $pharmacy["range_price_text"];
                $tmp["range_price_picture"]   		= $pharmacy["range_price_picture"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

$app->post('/admin/addpharmacypromotionitem' ,$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_typepromotion','id_asset','promotion_price_old','promotion_price_new','promotion_discount_amt','promotion_discount_pct','promotion_discount_number','promotion_buy_number','id_promotion'));
            $response = array();  
            // reading post params
            $id_promotion = $app->request->post('id_promotion');
			$id_typepromotion = $app->request->post('id_typepromotion');
			$id_asset = $app->request->post('id_asset');
            $promotion_price_old = $app->request->post('promotion_price_old');
            $promotion_price_new = $app->request->post('promotion_price_new');
			$promotion_discount_amt = $app->request->post('promotion_discount_amt');
			$promotion_discount_pct = $app->request->post('promotion_discount_pct');
            $promotion_discount_number = $app->request->post('promotion_discount_number');
            $promotion_buy_number = $app->request->post('promotion_buy_number');
			
			$data = array(
						  'id_promotion'=>$id_promotion,
						  'id_typepromotion'=>$id_typepromotion,
						  'id_asset'=>$id_asset,
						  'promotion_price_old'=>$promotion_price_old,
						  'promotion_price_new'=>$promotion_price_new,
						  'promotion_discount_amt'=>$promotion_discount_amt,
						  'promotion_discount_pct'=>$promotion_discount_pct,
						  'promotion_discount_number'=>$promotion_discount_number,
						  'promotion_buy_number'=>$promotion_buy_number
						  );
            $db = new DbHandler();
            $res = $db->addpharmacypromotionitem($data);
            if ($res == PROMOTION_SUCCESSFULLY) {
                $response["error"] = false; 
                $response["message"] = "Pharmacy promotion are successfully registered";
            } else if ($res == PROMOTION_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
			}
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editpharmacypromotionitem',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_promotion','id_typepromotion','id_asset','promotion_price_old','promotion_price_new','promotion_discount_amt','promotion_discount_pct','promotion_discount_number','promotion_buy_number'));
            $response = array();
            //reading post params
			$id_promotion = $app->request->post('id_promotion');
			$id_typepromotion = $app->request->post('id_typepromotion');
			$id_asset = $app->request->post('id_asset');
            $promotion_price_old = $app->request->post('promotion_price_old');
            $promotion_price_new = $app->request->post('promotion_price_new');
			$promotion_discount_amt = $app->request->post('promotion_discount_amt');
			$promotion_discount_pct = $app->request->post('promotion_discount_pct');
            $promotion_discount_number = $app->request->post('promotion_discount_number');
            $promotion_buy_number = $app->request->post('promotion_buy_number');
			
            $db   = new DbHandler();  
			$data = array(
						  'id_promotion'=>$id_promotion,
						  'id_typepromotion'=>$id_typepromotion,
						  'id_asset'=>$id_asset,
						  'promotion_price_old'=>$promotion_price_old,
						  'promotion_price_new'=>$promotion_price_new,
						  'promotion_discount_amt'=>$promotion_discount_amt,
						  'promotion_discount_pct'=>$promotion_discount_pct,
						  'promotion_discount_number'=>$promotion_discount_number,
						  'promotion_buy_number'=>$promotion_buy_number
						  ); 
			
            $res = $db->editpharmacypromotionitem($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deletepharmacypromotionitem',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_promotionitem'));
            $response = array();
            //reading post params
            $id_promotion   = $app->request->post('id_promotionitem');
            $db   = new DbHandler();
			$data = array('id_promotion'=>$id_promotion);
			
			
            $res = $db->deletepharmacypromotionitem($data); 
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "pharmacy promotion item are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while deleting";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });


$app->post('/addproductrating', $authenticate($app), function() use ($app) {
            // check for required params
			verifyRequiredParams(array('id_product','product_rating','product_rating_comments'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
			$product_rating = $app->request->post('product_rating');
            $product_rating_comments = $app->request->post('product_rating_comments');
			
			$data = array(
						  'id_product'=>$id_product,
						  'product_rating'=>$product_rating,
						  'product_rating_comments'=>$product_rating_comments
						  );
            $db = new DbHandler();
            $res = $db->addproductrating($data);
            if ($res == PRODUCTRATING_CREATED_SUCCESSFULLY) {
                $response["error"] = false; 
                $response["message"] = "thank you for your feedback";
            } else if ($res == PRODUCTRATING_CREATE_FAILED) {
                $response["error"] = true; 
                $response["message"] = "Oops! An error occurred while storing feedback";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/editproductrating',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_product'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
			$product_rating = $app->request->post('product_rating');
            $product_rating_comments = $app->request->post('product_rating_comments');
			$product_rating_active = $app->request->post('product_rating_active');
			
			$data = array(
						  'id_product'=>$id_product,
						  'product_rating'=>$product_rating,
						  'product_rating_comments'=>$product_rating_comments,
						  'product_rating_active'=>$product_rating_active
						  );
			 $db = new DbHandler();
            $res = $db->editproductrating($data);
            if ($res == PRODUCTRATING_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "thank you for updating your feedback";
            } else if ($res == PRODUCTRATING_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while storing feedback";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deleteproductrating',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_productrating'));
            $response = array();
            //reading post params
            $id_productrating   = $app->request->post('id_productrating');
            $db   = new DbHandler();
			
			$res = $db->usersessioncheck('product_rating','id_productrating',$id_productrating);
            $res = $db->deleteproductrating($id_productrating);
            if ($res == PRODUCTRATING_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "feedback deleted  ";
            } else if ($res == PRODUCTRATING_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while deleting feedback";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! feedback Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listproductrating',$authenticate($app), function() use ($app) { 
            global $user_id;
			checkloginuserisadmin();
			verifyRequiredParams(array('id_product'));
			$id_product = $app->request->get('id_product');
			
		    $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallproductrating($id_product);
            $response["error"] = false;
            $response["prod"] = array();
            // looping through result and preparing tasks array
            while ($prod = $result->fetch_array(MYSQLI_ASSOC)) {  
                $tmp = array();
                $tmp["user_id"]      	 = $prod["id"];
				$tmp["product_rating_date"]   	 = $prod["product_rating_date"];
                $tmp["product_rating"]    	   	 = $prod["product_rating"];
                $tmp["product_rating_comments"]   = $prod["product_rating_comments"];
              
                array_push($response["prod"], $tmp);
            }
            echoRespnse(200, $response); 
		});


/*today api*/
		$app->post('/admin/addproductcode', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_product','product_code', 'product_volume','id_coulour'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $product_code = $app->request->post('product_code');
            $product_volume = $app->request->post('product_volume');
			$id_coulour = $app->request->post('id_coulour');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
			
			$data = array(
						  'id_product'=>$id_product,
						  'product_code'=>$product_code,
						  'product_volume'=>$product_volume,
						  'id_coulour'=>$id_coulour,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
			
            $res = $db->productcode($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

		$app->post('/admin/editproductcode',$authenticate($app), function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id','id_product','product_code', 'product_volume','id_coulour'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');			
			$id_product = $app->request->post('id_product');
            $product_code = $app->request->post('product_code');
            $product_volume = $app->request->post('product_volume');
			$id_coulour = $app->request->post('id_coulour');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_product'=>$id_product,
						  'product_code'=>$product_code,
						  'product_volume'=>$product_volume,
						  'id_coulour'=>$id_coulour,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version,
						  );
			
            $res = $db->editproductcode($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

		
		$app->post('/admin/deleteproductcode',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteproductcode($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		
		$app->get('/admin/listproductcode',$authenticate($app), function() { 
            global $user_id;
			checkloginuserisadmin();
		    $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallproductcode();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["id_product"]   	 = $pharmacy["id_product"];
				$tmp["product_code"]   	 = $pharmacy["product_code"];
                $tmp["product_volume"]    	   	 = $pharmacy["product_volume"];
                $tmp["id_coulour"]   = $pharmacy["id_coulour"];
                $tmp["product_code_active"] 	 = $pharmacy["product_code_active"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
				
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});
		
		
		
		$app->post('/admin/adduseraccess', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_user','pharmacy_code','user_gps', 'id_role','user_access_date'));
            $response = array();
            // reading post params
			$id_user = $app->request->post('id_user');
            $pharmacy_code = $app->request->post('pharmacy_code');
            $user_gps = $app->request->post('user_gps');
			$id_role = $app->request->post('id_role');
            $user_access_date = $app->request->post('user_access_date');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
			
			$data = array(
						  'id_user'=>$id_user,
						  'pharmacy_code'=>$pharmacy_code,
						  'user_gps'=>$user_gps,
						  'id_role'=>$id_role,
						  'user_access_date'=>$user_access_date,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  
						  );
            $db = new DbHandler();+
			
            $res = $db->useraccess($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });		
		
		
		
		$app->post('/admin/edituseraccess',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id','pharmacy_code','user_gps', 'id_role','user_access_date'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');			
			$id_user = $app->request->post('id_user');
            $pharmacy_code = $app->request->post('pharmacy_code');
            $user_gps = $app->request->post('user_gps');
			$id_role = $app->request->post('id_role');
            $user_access_date = $app->request->post('user_access_date');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_user'=>$id_user,
						  'pharmacy_code'=>$pharmacy_code,
						  'user_gps'=>$user_gps,
						  'id_role'=>$id_role,
						  'user_access_date'=>$user_access_date,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edituseraccess($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
		
		
		$app->post('/admin/deleteuseraccess',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleteuseraccess($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });	
		
		
		
		
		$app->get('/admin/listuseraccess',$authenticate($app), function() { 
            global $user_id;
			checkloginuserisadmin();
		    $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getalluseraccess();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["id_user"]   	 = $pharmacy["id_user"];
				$tmp["pharmacy_code"]   	 = $pharmacy["pharmacy_code"];
                $tmp["user_gps"]    	   	 = $pharmacy["user_gps"];
                $tmp["id_role"]   = $pharmacy["id_role"];
                $tmp["user_access_date"] 	 = $pharmacy["user_access_date"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
				
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});
		
		
		$app->post('/admin/addrole', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_role','role_name'));
            $response = array();
            // reading post params
			$id_role = $app->request->post('id_role');
            $role_name = $app->request->post('role_name');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
			
			$data = array(
						  'id_role'=>$id_role,
						  'role_name'=>$role_name,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
			
            $res = $db->role($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
		
		$app->post('/admin/editrole',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_role','role_name'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');			
			$id_role = $app->request->post('id_role');
            $role_name = $app->request->post('role_name');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_role'=>$id_role,
						  'role_name'=>$role_name,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->editrole($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

		
		$app->post('/admin/deleterole',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			 
            $res = $db->deleterole($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });

		$app->get('/admin/listrole',$authenticate($app), function() { 
            global $user_id;
			checkloginuserisadmin();
		    $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallrole();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["id_role"]   	 = $pharmacy["id_role"];
				$tmp["role_name"]   	 = $pharmacy["role_name"];
                $tmp["role_active"]    	   	 = $pharmacy["role_active"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
				
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});

		$app->post('/admin/addrange', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_range','id_laboratory', 'range_name', 'id_typerange'));
            $response = array();
            // reading post params
			$id_range = $app->request->post('id_range');
            $id_laboratory = $app->request->post('id_laboratory');
            $range_name = $app->request->post('range_name');
			$id_typerange = $app->request->post('id_typerange');
            $id_picture = $app->request->post('id_picture');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
			
			$data = array(
						  'id_range'=>$id_range,
						  'id_laboratory'=>$id_laboratory,
						  'range_name'=>$range_name,
						  'id_typerange'=>$id_typerange,
						  'id_picture'=>$id_picture,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  
						  );
            $db = new DbHandler();
			
            $res = $db-> addrange($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });


		$app->post('/admin/editrange',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_range','id_laboratory', 'range_name', 'id_typerange'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');			
			$id_range = $app->request->post('id_range');
            $id_laboratory = $app->request->post('id_laboratory');
            $range_name = $app->request->post('range_name');
			$id_typerange = $app->request->post('id_typerange');
            $id_picture = $app->request->post('id_picture');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_range'=>$id_range,
						  'id_laboratory'=>$id_laboratory,
						  'range_name'=>$range_name,
						  'id_typerange'=>$id_typerange,
						  'id_picture'=>$id_picture,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->editrange($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });

		$app->post('/admin/deleterange',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deleterange($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }else if($res ==  USER_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! User Doenst exist,Please register";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response 
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listrange',$authenticate($app), function() { 
		checkloginuserisadmin();
		global $user_id;
		$response = array();
		$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getallrange();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["user_id"]      	 = $pharmacy["id"];
		$tmp["id_range"]   	 = $pharmacy["id_range"];
		$tmp["id_laboratory"]   	 = $pharmacy["id_laboratory"];
		$tmp["range_name"]    	   	 = $pharmacy["range_name"];
		$tmp["id_typerange"]   	 = $pharmacy["id_typerange"];
		$tmp["id_picture"]   	 = $pharmacy["id_picture"];
		$tmp["range_active"]    	   	 = $pharmacy["range_active"];
		$tmp["version"]       	 = $pharmacy["version"];
		$tmp["id_user_version"]  = $pharmacy["id_user_version"];
		$tmp["version_date"]     = $pharmacy["version_date"];
		
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});
/*end of api*/

$app->post('/user/addmember', $authenticate($app), function() use ($app) {
            // check for required params
		    verifyRequiredParams(array('member_name','dob'));
            $response = array();
            $db = new DbHandler();
			
			if(!isset($_FILES['uploads'])){
				$picid =  $app->request->post('picture_id');
			}else{
				if($_FILES['uploads']['name'] != ''){
					$picid = $db->uploadFile($_FILES);
				}else{
					$picid =  $app->request->post('picture_id');
				}
			}
			
			
			
		    // reading post params
            $id_user = $_SESSION['user']['id'];
            $member_name = $app->request->post('member_name');
			$mem_dob = $app->request->post('dob');
			$id_picture = $picid;
			$data = array(
						  'id_user'=>$id_user,
						  'member_name'=>$member_name,
						  'mem_dob'=>$mem_dob,
						  'id_picture'=>$id_picture
						  );
			
            $res = $db-> addmember($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully added a member";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            } else if ($picid == EMPTY_FILE) {
                $response["error"] = true;
                $response["message"] = "Sorry,empty upload";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
$app->post('/user/editmember',$authenticate($app), function() use ($app) {
            // check for required params
		    verifyRequiredParams(array('id_member'));
			$db   = new DbHandler();
            $response = array();
            //reading post params
			$id_member = $app->request->post('id_member');			
            $member_name = $app->request->post('member_name'); 
			$mem_dob = $app->request->post('mem_dob');
			
			if(!isset($_FILES['uploads'])){
				$id_picture =  $app->request->post('picture_id');
			}else{
				if($_FILES['uploads']['name'] != ''){ 
					$id_picture = $db->uploadFile($_FILES);
				}else{
					$id_picture =  $app->request->post('picture_id');
				}
			}
			
   			
			$data = array('id_member'=>$id_member,
						  'member_name'=>$member_name,
						  'mem_dob'=>$mem_dob,
						  'picture_id'=>$picture_id,
						  'id_picture'=>$id_picture
						  );
			
            $res = $db->editmember($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == YOU_CANNOT_EDIT) {
                $response["error"] = true;
                $response["message"] = "Oops! You are not authorised to edit this data";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/user/deletemember',$authenticate($app), function() use ($app) {
            // check for required params
			verifyRequiredParams(array('id_member'));
            $response = array();
            //reading post params
            $id_member   = $app->request->post('id_member');
			$db   = new DbHandler();
			$data = array('id_member'=>$id_member);
			$res = $db->deletemember($data);
			if ($res == USER_DELETED_SUCCESSFULLY) {
				$response["error"] = false;
				$response["message"] = "user are successfully deleted";
			} else if ($res == USER_DELETED_FAILED) {
				$response["error"] = true;
				$response["message"] = "Oops! An error occurred while registereing";
			}else if($res ==  CANNOT_DELETE){
				$response["error"] = true;
				$response["message"] = "Oops! You can not delete this data";
			}
			// echo json response 
			echoRespnse(201, $response);
});
 
$app->get('/user/listmember',$authenticate($app), function() { 
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getallmember();
	$response["error"] = false;
	$response["details"] = array();
	$pageURL = $_SERVER["SERVER_NAME"].'/v1/uploads';
	// looping through result and preparing tasks array
	while ($details = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id_member"]   	 = $details["id_member"];
		$tmp["member_name"]   = $details["member_name"];
		$tmp["id_picture"]   	= $details["id_picture"];
		$tmp["mem_dob"]   = $details["mem_dob"];
		$tmp["picture_url"]  = 'http://'.$pageURL.'/'.$details["picture_name"];
		array_push($response["details"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/user/addfamilytag', $authenticate($app), function() use ($app) {
            // check for required params
			verifyRequiredParams(array('id_family_tag','id_family', 'id_tag'));
            $response = array();
            // reading post params
			$id_family_tag		 = $app->request->post('id_family_tag');
            $id_family 			 = $app->request->post('id_family');
            $id_tag				 = $app->request->post('id_tag');
			$id_family_next		 = $app->request->post('id_family_next');
			$family_tag_active	 = $app->request->post('family_tag_active');
			$version			 = 0;
            $id_user_version	 = $_SESSION['user']['id'];;
			
			
			$data = array(
						  'id_family_tag'=>$id_family_tag,
						  'id_family'=>$id_family,
						  'id_tag'=>$id_tag,
						  'id_family_next'=>$id_family_next,
						  'family_tag_active'=>$family_tag_active,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
			
            $res = $db-> addfamilytag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/editfamilytag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_family_tag','id_family', 'id_tag', 'id_family_next'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');			
			$id_family_tag		 = $app->request->post('id_family_tag');
            $id_family 			 = $app->request->post('id_family');
            $id_tag				 = $app->request->post('id_tag');
			$id_family_next		 = $app->request->post('id_family_next');
			$version			 = 1;
            $id_user_version	 = $_SESSION['user']['id'];
			$version_date 		 = $app->request->post('version_date');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_family_tag'=>$id_family_tag,
						  'id_family'=>$id_family,
						  'id_tag'=>$id_tag,
						  'id_family_next'=>$id_family_next,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
						  );
			
            $res = $db->editfamilytag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/deletefamilytag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletefamilytag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listfamilytag',$authenticate($app), function() { 
			checkloginuserisadmin();
			global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getallfamilytag();
            $response["error"] = false;
            $response["pharmacy"] = array();
            // looping through result and preparing tasks array
            while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	 = $pharmacy["id"];
                $tmp["id_family_tag"]    = $pharmacy["id_family_tag"];
				$tmp["id_family"]   	 = $pharmacy["id_family"];
                $tmp["id_tag"]    	   	 = $pharmacy["id_tag"];
				$tmp["id_family_next"]   = $pharmacy["id_family_next"];
				$tmp["family_tag_active"]= $pharmacy["family_tag_active"];
               	$tmp["version"]       	 = $pharmacy["version"];
				$tmp["id_user_version"]  = $pharmacy["id_user_version"];
                $tmp["version_date"]     = $pharmacy["version_date"];
				
              
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});




$app->post('/admin/addcontact', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('contact_email', 'contact_subject', 'contact_form'));
            $response = array();
            // reading post params
			$contact_date = $app->request->post('contact_date');
            $contact_email = $app->request->post('contact_email');
            $contact_subject = $app->request->post('contact_subject');
			$contact_form = $app->request->post('contact_form');
			
			
			$data = array(
						  'contact_date'=>$contact_date,
						  'contact_email'=>$contact_email,
						  'contact_subject'=>$contact_subject,
						  'contact_form'=>$contact_form
						  );
            $db = new DbHandler();
			
            $res = $db-> addcontact($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
 $app->post('/admin/editcontact',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('contact_id','contact_email', 'contact_subject', 'contact_form'));
            $response = array();
            //reading post params
			$contact_id = $app->request->post('contact_id');			
			$contact_email = $app->request->post('contact_email');
            $contact_subject = $app->request->post('contact_subject');
            $contact_form = $app->request->post('contact_form');
			
            $db   = new DbHandler();
			$data = array('contact_id'=>$contact_id,
						  'contact_email'=>$contact_email,
						  'contact_subject'=>$contact_subject,
						  'contact_form'=>$contact_form
						  );
			
            $res = $db->editcontact($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletecontact',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('contact_id'));
            $response = array();
            //reading post params
            $contact_id   = $app->request->post('contact_id');
            $db   = new DbHandler();
			$data = array('contact_id'=>$contact_id);
			
			
            $res = $db->deletecontact($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listcontact',$authenticate($app), function() { 
	checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getallcontact();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["contact_id"]      	 = $pharmacy["contact_id"];
		$tmp["contact_date"]   	 = $pharmacy["contact_date"];
		$tmp["contact_email"]   	 = $pharmacy["contact_email"];
		$tmp["contact_subject"]    = $pharmacy["contact_subject"];
		$tmp["contact_form"]   = $pharmacy["contact_form"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});


$app->post('/admin/test_ques', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_ques', 'id_surv', 'ques_name','id_typeques','id_ques_next','ques_value','ques_desc'));
            $response = array();
            // reading post params
			$id_ques = $app->request->post('id_ques');
            $id_surv = $app->request->post('id_surv');
            $ques_name = $app->request->post('ques_name');
			$id_typeques = $app->request->post('id_typeques');
			$id_ques_next = $app->request->post('id_ques_next');
            $ques_value = $app->request->post('ques_value');
            $ques_desc = $app->request->post('ques_desc');
			$id_usre_ds = $app->request->post('id_usre_ds');
			$usre_ds_mem = $app->request->post('usre_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_usre_version = $app->request->post('id_usre_version');

			$data = array(
						  'id_ques'=>$id_ques,
						  'id_surv'=>$id_surv,
						  'ques_name'=>$ques_name,
						  'id_typeques'=>$id_typeques,
						  'id_ques_next'=>$id_ques_next,
						  'ques_value'=>$ques_value,
						  'ques_desc'=>$ques_desc,
						  'id_usre_ds'=>$id_usre_ds,
						  'usre_ds_mem'=>$usre_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_usre_version'=>$id_usre_version
						  );
            $db = new DbHandler();
            $res = $db-> testques($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
 $app->post('/admin/edittest_ques',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array( 'id_ques', 'id_surv','ques_name','id_typeques','id_ques_next','ques_value','ques_desc','id_usre_ds','usre_ds_mem','version_nbr','id_usre_version'));
            $response = array();
            //reading post params
			$id_ques = $app->request->post('id_ques');
            $id_surv = $app->request->post('id_surv');
            $ques_name = $app->request->post('ques_name');
			$id_typeques = $app->request->post('id_typeques');
			$id_ques_next = $app->request->post('id_ques_next');
            $ques_value = $app->request->post('ques_value');
            $ques_desc = $app->request->post('ques_desc');
			$id_usre_ds = $app->request->post('id_usre_ds');
			$usre_ds_mem = $app->request->post('usre_ds_mem');
            $version_nbr = $app->request->post('version_nbr'); 
			$id_usre_version = $app->request->post('id_usre_version');
			
            $db   = new DbHandler();
			$data = array(
						  'id_ques'=>$id_ques,
						  'id_surv'=>$id_surv,
						  'ques_name'=>$ques_name,
						  'id_typeques'=>$id_typeques,
						  'id_ques_next'=>$id_ques_next,
						  'ques_value'=>$ques_value,
						  'ques_desc'=>$ques_desc,
						  'id_usre_ds'=>$id_usre_ds,
						  'usre_ds_mem'=>$usre_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_usre_version'=>$id_usre_version
						  );
			
            $res = $db->edittestques($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_ques',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_ques'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id_ques');
            $db   = new DbHandler();
			$data = array('id_ques'=>$id_ques);
			
			
            $res = $db->deletetestques($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_ques',$authenticate($app), function() use ($app){ 
			checkloginuserisadmin();
			verifyRequiredParams(array('survey_id'));
			$survey_id = $app->request->get('survey_id');
			$data = array('survey_id'=>$survey_id);
			$response = array();
			$db = new DbHandler($data);
			// fetching all user tasks
			$result = $db->list_testsurvey($data);
			$response["error"] = false;
			$response["test_survey"] = array();
			// looping through result and preparing tasks array
			while ($test = $result->fetch_array(MYSQLI_ASSOC)) {
				$tmp = array();
				$tmp["ques_name"]   	 = $test["ques_name"];
				$tmp["id_typeques"]   	 = $test["id_typeques"];
				$tmp["id_ques_next"]    = $test["id_ques_next"];
				$tmp["ques_value"]   = $test["ques_value"];
				$tmp["ques_desc"]   	 = $test["ques_desc"];
				$tmp["nx_ques_name"]   	 = $test["nx_ques_name"];
				$tmp["nx_id_typeques"]   	 = $test["nx_id_typeques"];
				$tmp["nx_id_ques_next"]    = $test["nx_id_ques_next"];
				$tmp["nx_ques_value"]   = $test["nx_ques_value"];
				$tmp["nx_ques_desc"]   	 = $test["nx_ques_desc"];
				
			  
				array_push($response["test_survey"], $tmp);
			}
			echoRespnse(200, $response); 
});

$app->get('/admin/listtest_ans',$authenticate($app), function() use ($app){ 
			checkloginuserisadmin();
			verifyRequiredParams(array('id_ques'));
			$id_ques = $app->request->get('id_ques');
			$data = array('id_ques'=>$id_ques);
			$response = array();
			$db = new DbHandler();
			// fetching all user tasks
			$result = $db->listtest_ans($data);
			$response["error"] = false;
			$response["test_ans_survey"] = array();
			// looping through result and preparing tasks array
			while ($test = $result->fetch_array(MYSQLI_ASSOC)) {
				$tmp = array();
				$tmp["ans_order"]   	 = $test["ans_order"];
				$tmp["ans_value"]   	 = $test["ans_value"]; 
				$tmp["ans_desc"]    = $test["ans_desc"];
				$tmp["id_prod_ans"]   = $test["id_prod_ans"];
				$tmp["ques_name"]   	 = $test["ques_name"];
				$tmp["id_typeques"]   	 = $test["id_typeques"];
				$tmp["id_ques_next"]    = $test["id_ques_next"];
				$tmp["ques_value"]   = $test["ques_value"];
				$tmp["ques_desc"]   	 = $test["ques_desc"];
				
			  
				array_push($response["test_ans_survey"], $tmp);
			}
			echoRespnse(200, $response); 
});


$app->post('/admin/test_ques_tag', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_ques_tag', 'id_ques', 'id_tag','flg_ques_tag_alt','id_usre_ds','usre_ds_mem'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_ques_tag = $app->request->post('id_ques_tag');
            $id_ques = $app->request->post('id_ques');
            $tag = $app->request->post('id_tag');
			$id_tag = $db->testtag($tag);
			$flg_ques_tag_alt = $app->request->post('flg_ques_tag_alt');
			$id_usre_ds = $app->request->post('id_usre_ds');
            $usre_ds_mem = $app->request->post('usre_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_usre_version = $app->request->post('id_usre_version');

			$data = array(
						  'id_ques_tag'=>$id_ques_tag,
						  'id_ques'=>$id_ques,
						  'id_tag'=>$id_tag,
						  'flg_ques_tag_alt'=>$flg_ques_tag_alt,
						  'id_usre_ds'=>$id_usre_ds,
						  'usre_ds_mem'=>$usre_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_usre_version'=>$id_usre_version
						  );
           
            $res = $db-> testquestag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

 $app->post('/admin/edittest_ques_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_ques_tag', 'id_ques', 'id_tag','flg_ques_tag_alt','id_usre_ds','usre_ds_mem'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_ques_tag = $app->request->post('id_ques_tag');
            $id_ques = $app->request->post('id_ques');
            $id_tag = $app->request->post('id_tag');
			$flg_ques_tag_alt = $app->request->post('flg_ques_tag_alt');
			$id_usre_ds = $app->request->post('id_usre_ds');
            $usre_ds_mem = $app->request->post('usre_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_usre_version = $app->request->post('id_usre_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_ques_tag'=>$id_ques_tag,
						  'id_ques'=>$id_ques,
						  'id_tag'=>$id_tag,
						  'flg_ques_tag_alt'=>$flg_ques_tag_alt,
						  'id_usre_ds'=>$id_usre_ds,
						  'usre_ds_mem'=>$usre_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_usre_version'=>$id_usre_version
						  );
			
            $res = $db->edittestquestag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_ques_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->deletetestquestag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_ques_tag',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_ques_tag();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"];
		$tmp["id_ques"]   	 = $pharmacy["id_ques"];
		$tmp["id_surv"]   	 = $pharmacy["id_surv"];
		$tmp["ques_name"]    = $pharmacy["ques_name"];
		$tmp["id_ques_next"]   = $pharmacy["id_ques_next"];
		$tmp["ques_value"]   	 = $pharmacy["ques_value"];
		$tmp["ques_desc"]   	 = $pharmacy["ques_desc"];
		$tmp["id_usre_ds"]    = $pharmacy["id_usre_ds"];
		$tmp["usre_ds_mem"]   = $pharmacy["usre_ds_mem"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_question', $authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id_question', 'id_test', 'question_value','question_description','question_order','question_description'));
            $response = array();
            // reading post params
			$id_question = $app->request->post('id_question');
            $id_test = $app->request->post('id_test');
            $question_value = $app->request->post('question_value');
			$question_description = $app->request->post('question_description');
			$question_order = $app->request->post('question_order');
            $version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_question'=>$id_question,
						  'id_test'=>$id_test,
						  'question_value'=>$question_value,
						  'question_description'=>$question_description,
						  'question_order'=>$question_order,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> testquestion($data);
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
 $app->post('/admin/edittest_question',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
			// check for required params
            verifyRequiredParams(array('id','id_question', 'id_test', 'question_value','question_description','question_order'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_question = $app->request->post('id_question');
            $id_test = $app->request->post('id_test');
            $question_value = $app->request->post('question_value');
			$question_description = $app->request->post('question_description');
			$question_order = $app->request->post('question_order');
            $version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_question'=>$id_question,
						  'id_test'=>$id_test,
						  'question_value'=>$question_value,
						  'question_description'=>$question_description,
						  'question_order'=>$question_order,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittestquestion($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});


$app->post('/admin/deletetest_question',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		   
		    // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetestquestion($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_question', $authenticate($app), $authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_question();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"]; 
		$tmp["id_question"]   	 = $pharmacy["id_question"];
		$tmp["id_test"]   	 = $pharmacy["id_test"]; 
		$tmp["question_value"]    = $pharmacy["question_value"];
		$tmp["question_description"]   = $pharmacy["question_description"];
		$tmp["question_description"]   	 = $pharmacy["question_order"];
		$tmp["version"]   	 = $pharmacy["version"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_question_tag', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_question', 'id_tag'));
            $response = array();
            // reading post params
			$id_question = $app->request->post('id_question');
            $id_tag = $app->request->post('id_tag');
            $version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_question'=>$id_question,
						  'id_tag'=>$id_tag,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> testquestiontag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
  $app->post('/admin/edittest_question_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_question', 'id_tag'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_question = $app->request->post('id_question');
            $id_tag = $app->request->post('id_tag');
            $version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_question'=>$id_question,
						  'id_tag'=>$id_tag,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittestquestiontag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_question_tag',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetestquestiontag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_question_tag',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_question_tag();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"]; 
		$tmp["id_question"]   	 = $pharmacy["id_question"];
		$tmp["id_tag"]   	 = $pharmacy["id_tag"]; 
		$tmp["version"]   	 = $pharmacy["version"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});


$app->post('/admin/test_surv', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_surv', 'cod_surv','surv_name','surv_desc','id_ques_start','id_user_ds','user_ds_mem'));
            $response = array();
            // reading post params
			$id_surv = $app->request->post('id_surv');
            $cod_surv = $app->request->post('cod_surv');
			$surv_name = $app->request->post('surv_name');
            $surv_desc = $app->request->post('surv_desc');
			$id_ques_start = $app->request->post('id_ques_start');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
			$id_surv = $app->request->post('id_surv');
            $cod_surv = $app->request->post('cod_surv');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_surv'=>$id_surv,
						  'cod_surv'=>$cod_surv,
						  'surv_name'=>$surv_name,
						  'surv_desc'=>$surv_desc,
						  'id_ques_start'=>$id_ques_start,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'id_surv'=>$id_surv,
						  'cod_surv'=>$cod_surv,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> testsurv($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

  $app->post('/admin/edittest_surv',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_surv', 'cod_surv','surv_name'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_surv = $app->request->post('id_surv');
            $cod_surv = $app->request->post('cod_surv');
			$surv_name = $app->request->post('surv_name');
            $surv_desc = $app->request->post('surv_desc');
			$id_ques_start = $app->request->post('id_ques_start');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_surv'=>$id_surv,
						  'cod_surv'=>$cod_surv,
						  'surv_name'=>$surv_name,
						  'surv_desc'=>$surv_desc,
						  'id_ques_start'=>$id_ques_start,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittestsurv($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_surv',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetestsurv($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_surv',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_surv();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"]; 
		$tmp["id_surv"]   	 = $pharmacy["id_surv"];
		$tmp["cod_surv"]   	 = $pharmacy["cod_surv"];
		$tmp["surv_name"]   	 = $pharmacy["surv_name"];
		$tmp["surv_desc"]   	 = $pharmacy["surv_desc"];
		$tmp["id_ques_start"]   	 = $pharmacy["id_ques_start"];
		$tmp["id_user_ds"]   	 = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]   	 = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]   	 = $pharmacy["version_nbr"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_surv_tag', $authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id_surv_tag', 'id_surv','id_tag','flg_surv_tag_alt','id_user_ds','user_ds_mem'));
            $response = array();
            // reading post params
			$id_surv_tag = $app->request->post('id_surv_tag');
            $id_surv = $app->request->post('id_surv');
			$id_tag = $app->request->post('id_tag');
            $flg_surv_tag_alt = $app->request->post('flg_surv_tag_alt');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_surv_tag'=>$id_surv_tag,
						  'id_surv'=>$id_surv,
						  'id_tag'=>$id_tag,
						  'flg_surv_tag_alt'=>$flg_surv_tag_alt,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_surv_tag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });


  $app->post('/admin/edittest_surv_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_surv_tag', 'id_surv','id_tag','flg_surv_tag_alt','id_user_ds','user_ds_mem'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_surv_tag = $app->request->post('id_surv_tag');
            $id_surv = $app->request->post('id_surv');
			$id_tag = $app->request->post('id_tag');
            $flg_surv_tag_alt = $app->request->post('flg_surv_tag_alt');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_surv_tag'=>$id_surv_tag,
						  'id_surv'=>$id_surv,
						  'id_tag'=>$id_tag,
						  'flg_surv_tag_alt'=>$flg_surv_tag_alt,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_surv_tag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_surv_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetest_surv_tag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_surv_tag',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_surv_tag();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"]; 
		$tmp["id_surv_tag"]   	 = $pharmacy["id_surv_tag"];
		$tmp["id_surv"]   	 = $pharmacy["id_surv"];
		$tmp["id_tag"]   	 = $pharmacy["id_tag"];
		$tmp["flg_surv_tag_alt"]   	 = $pharmacy["flg_surv_tag_alt"];
		$tmp["id_user_ds"]   	 = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]   	 = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]   	 = $pharmacy["version_nbr"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_tag', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_tag', 'cod_tag','tag_name','tag_desc','flg_tag_form','id_user_ds'));
            $response = array();
            // reading post params
			$id_tag = $app->request->post('id_tag');
            $cod_tag = $app->request->post('cod_tag');
			$tag_name = $app->request->post('tag_name');
            $tag_desc = $app->request->post('tag_desc');
			$flg_tag_form = $app->request->post('flg_tag_form');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_tag'=>$id_tag,
						  'cod_tag'=>$cod_tag,
						  'tag_name'=>$tag_name,
						  'tag_desc'=>$tag_desc,
						  'flg_tag_form'=>$flg_tag_form,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_tag($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });
 
$app->post('/admin/edittest_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_tag', 'cod_tag','tag_name','tag_desc','flg_tag_form','id_user_ds'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_tag = $app->request->post('id_tag');
            $cod_tag = $app->request->post('cod_tag');
			$tag_name = $app->request->post('tag_name');
            $tag_desc = $app->request->post('tag_desc');
			$flg_tag_form = $app->request->post('flg_tag_form');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_tag'=>$id_tag,
						  'cod_tag'=>$cod_tag,
						  'tag_name'=>$tag_name,
						  'tag_desc'=>$tag_desc,
						  'flg_tag_form'=>$flg_tag_form,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_tag($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_tag',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetest_tag($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_tag',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_tag();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 = $pharmacy["id"]; 
		$tmp["id_tag"]   	 = $pharmacy["id_tag"];
		$tmp["cod_tag"]   	 = $pharmacy["cod_tag"];
		$tmp["tag_name"]   	 = $pharmacy["tag_name"];
		$tmp["flg_surv_ttag_descag_alt"]   	 = $pharmacy["tag_desc"];
		$tmp["flg_tag_form"]   	 = $pharmacy["flg_tag_form"];
		$tmp["id_user_ds"]   	 = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]   	 = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]   	 = $pharmacy["version_nbr"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_typeques', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_typeques', 'code_typeques','typeques_name','typeques_desc','id_user_ds','user_ds_mem'));
            $response = array();
            // reading post params
			$id_typeques = $app->request->post('id_typeques');
            $code_typeques = $app->request->post('code_typeques');
			$typeques_name = $app->request->post('typeques_name');
            $typeques_desc = $app->request->post('typeques_desc');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_typeques'=>$id_typeques,
						  'code_typeques'=>$code_typeques,
						  'typeques_name'=>$typeques_name,
						  'typeques_desc'=>$typeques_desc,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_typeques($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

$app->post('/admin/edittest_typeques',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_typeques', 'code_typeques','typeques_name','typeques_desc','id_user_ds','user_ds_mem'));
            $response = array();
            //reading post params
			$id_typeques = $app->request->post('id_typeques');
            $code_typeques = $app->request->post('code_typeques');
			$typeques_name = $app->request->post('typeques_name');
            $typeques_desc = $app->request->post('typeques_desc');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array(
						  'id_typeques'=>$id_typeques,
						  'code_typeques'=>$code_typeques,
						  'typeques_name'=>$typeques_name,
						  'typeques_desc'=>$typeques_desc,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_typeques($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response); 
});

$app->post('/admin/deletetest_typeques',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
			verifyRequiredParams(array('id_typeques'));
            $response = array();
            //reading post params
            $id_typeques   = $app->request->post('id_typeques');
            $db   = new DbHandler();
			$data = array('id_typeques'=>$id_typeques);
			
            $res = $db->deletetest_typeques($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_typeques',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_typeques();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id_typeques"]   	 = $pharmacy["id_typeques"];
		$tmp["code_typeques"]   	 = $pharmacy["code_typeques"];
		$tmp["typeques_name"]   	 = $pharmacy["typeques_name"];
		$tmp["typeques_desc"]   	 = $pharmacy["typeques_desc"];
		$tmp["id_user_ds"]   	 = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]   	 = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]   	 = $pharmacy["version_nbr"];
		$tmp["id_user_version"]    = $pharmacy["id_user_version"];
		$tmp["version_date"]   = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_user', $authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id_user', 'user_firstname','user_lastname','user_login','user_password'));
            $response = array();
            // reading post params
			$id_user = $app->request->post('id_user');
            $user_firstname = $app->request->post('user_firstname');
			$user_lastname = $app->request->post('user_lastname');
            $user_login = $app->request->post('user_login');
            $user_password = $app->request->post('user_password');
			$user_create_date = $app->request->post('user_create_date');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_user'=>$id_user,
						  'user_firstname'=>$user_firstname,
						  'user_lastname'=>$user_lastname,
						  'user_login'=>$user_login,
						  'user_password'=>$user_password,
						  'user_create_date'=>$user_create_date,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_user($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

$app->post('/admin/edittest_user',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
		    verifyRequiredParams(array('id','id_user', 'user_firstname','user_lastname','user_login','user_password'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_user = $app->request->post('id_user');
            $user_firstname = $app->request->post('user_firstname');
			$user_lastname = $app->request->post('user_lastname');
            $user_login = $app->request->post('user_login');
            $user_password = $app->request->post('user_password');
			$user_create_date = $app->request->post('user_create_date');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_user'=>$id_user,
						  'user_firstname'=>$user_firstname,
						  'user_lastname'=>$user_lastname,
						  'user_login'=>$user_login,
						  'user_password'=>$user_password,
						  'user_create_date'=>$user_create_date,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_user($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_user',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
	        verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetest_user($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_user',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_user();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	 	 = $pharmacy["id"]; 
		$tmp["id_user"]   		 = $pharmacy["id_user"];
		$tmp["user_firstname"]   = $pharmacy["user_firstname"];
		$tmp["user_lastname"]    = $pharmacy["user_lastname"];
		$tmp["user_login"]   	 = $pharmacy["user_login"];
		$tmp["user_password"]    = $pharmacy["user_password"];
		$tmp["user_create_date"] = $pharmacy["user_create_date"];
		$tmp["id_user_ds"]   	 = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]   	 = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]   	 = $pharmacy["version_nbr"];
		$tmp["id_user_version"]  = $pharmacy["id_user_version"];
		$tmp["version_date"]  	 = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_user_ans', $authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id_user_ans', 'id_user_ques','user_ans_order','id_ans'));
            $response = array();
            // reading post params
			$id_user_ans = $app->request->post('id_user_ans');
            $id_user_ques = $app->request->post('id_user_ques');
			$user_ans_order = $app->request->post('user_ans_order');
            $id_ans = $app->request->post('id_ans');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_user_ans'=>$id_user_ans,
						  'id_user_ques'=>$id_user_ques,
						  'user_ans_order'=>$user_ans_order,
						  'id_ans'=>$id_ans,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_user_ans($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

$app->post('/admin/edittest_user_ans',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
			// check for required params
            verifyRequiredParams(array('id','id_user_ans', 'id_user_ques','user_ans_order','id_ans'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_user_ans = $app->request->post('id_user_ans');
            $id_user_ques = $app->request->post('id_user_ques');
			$user_ans_order = $app->request->post('user_ans_order');
            $id_ans = $app->request->post('id_ans');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						  'id_user_ans'=>$id_user_ans,
						  'id_user_ques'=>$id_user_ques,
						  'user_ans_order'=>$user_ans_order,
						  'id_ans'=>$id_ans,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_user_ans($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_user_ans',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetest_user_ans($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_user_ans',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_user_ans();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	   = $pharmacy["id"]; 
		$tmp["id_user_ans"]    = $pharmacy["id_user_ans"];
		$tmp["id_user_ques"]   = $pharmacy["id_user_ques"];
		$tmp["user_ans_order"] = $pharmacy["user_ans_order"];
		$tmp["id_ans"]   	   = $pharmacy["id_ans"];
		$tmp["id_user_ds"]     = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]    = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]    = $pharmacy["version_nbr"];
		$tmp["id_user_version"]  = $pharmacy["id_user_version"];
		$tmp["version_date"]  	 = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_user_surv', $authenticate($app), function() use ($app) {
			checkloginuserisadmin();
			// check for required params
            verifyRequiredParams(array('id_user_surv', 'id_user','id_surv','user_surv_date'));
            $response = array();
            // reading post params
			$id_user_surv = $app->request->post('id_user_surv');
            $id_user = $app->request->post('id_user');
			$id_surv = $app->request->post('id_surv');
            $user_surv_date = $app->request->post('user_surv_date');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_user_surv'=>$id_user_surv,
						  'id_user'=>$id_user,
						  'id_surv'=>$id_surv,
						  'user_surv_date'=>$user_surv_date,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_user_surv($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });

$app->post('/admin/edittest_user_surv',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id','id_user_surv', 'id_user','id_surv','user_surv_date'));
            $response = array();
            //reading post params
			$id = $app->request->post('id');
			$id_user_surv = $app->request->post('id_user_surv');
            $id_user = $app->request->post('id_user');
			$id_surv = $app->request->post('id_surv');
            $user_surv_date = $app->request->post('user_surv_date');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');
			
            $db   = new DbHandler();
			$data = array('id'=>$id,
						 'id_user_surv'=>$id_user_surv,
						  'id_user'=>$id_user,
						  'id_surv'=>$id_surv,
						  'user_surv_date'=>$user_surv_date,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
			
            $res = $db->edittest_user_surv($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data  successfully Edited";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
});

$app->post('/admin/deletetest_user_surv',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
			// check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
            $res = $db->deletetest_user_surv($data);
            if ($res == PHARMA_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == PHARMA_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response 
            echoRespnse(201, $response);
});

$app->get('/admin/listtest_user_surv',$authenticate($app), function() { 
			checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getalltest_user_surv();
	$response["error"] = false;
	$response["pharmacy"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	   = $pharmacy["id"]; 
		$tmp["id_user_surv"]    = $pharmacy["id_user_surv"];
		$tmp["id_user"]   = $pharmacy["id_user"];
		$tmp["id_surv"] = $pharmacy["id_surv"];
		$tmp["user_surv_date"]   	   = $pharmacy["user_surv_date"];
		$tmp["id_user_ds"]     = $pharmacy["id_user_ds"];
		$tmp["user_ds_mem"]    = $pharmacy["user_ds_mem"];
		$tmp["version_nbr"]    = $pharmacy["version_nbr"];
		$tmp["id_user_version"]  = $pharmacy["id_user_version"];
		$tmp["version_date"]  	 = $pharmacy["version_date"];
	  
		array_push($response["pharmacy"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/test_proud',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
		    // check for required params
            verifyRequiredParams(array('id_prod', 'cod_prod','id_labo','id_range','prod_name','id_form'));
            $response = array();
            // reading post params
			$id_prod = $app->request->post('id_prod');
            $cod_prod = $app->request->post('cod_prod');
			$id_labo = $app->request->post('id_labo');
            $id_range = $app->request->post('id_range');
			$prod_name = $app->request->post('prod_name');
            $id_form = $app->request->post('id_form');
			$id_unit = $app->request->post('id_unit');
            $id_prodstatus = $app->request->post('id_prodstatus');
			$prod_mem = $app->request->post('prod_mem');
			$id_user_ds = $app->request->post('id_user_ds');
            $user_ds_mem = $app->request->post('user_ds_mem');
            $version_nbr = $app->request->post('version_nbr');
			$id_user_version = $app->request->post('id_user_version');

			$data = array(
						  'id_prod'=>$id_prod,
						  'cod_prod'=>$cod_prod,
						  'id_labo'=>$id_labo,
						  'id_range'=>$id_range,
						  'prod_name'=>$prod_name,
						  'id_form'=>$id_form,
						  'id_unit'=>$id_unit,
						  'id_prodstatus'=>$id_prodstatus,
						  'prod_mem'=>$prod_mem,
						  'id_user_ds'=>$id_user_ds,
						  'user_ds_mem'=>$user_ds_mem,
						  'version_nbr'=>$version_nbr,
						  'id_user_version'=>$id_user_version
						  );
            $db = new DbHandler();
            $res = $db-> test_proud($data);
            if ($res == USER_CREATED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
 });


$app->post('/admin/addquestion', function() use ($app) {
	checkloginuserisadmin();
            // check for required params
            //verifyRequiredParams(array('question_name', 'question_description','answer_order','answer','next_question','correct_answers'));
            $response = array();
            // reading post params
			$question_name = $app->request->post('name');
            $question = $app->request->post('question');
			$question_tag = $app->request->post('tag');
			$question_description = $app->request->post('description');
			$surveyid = $app->request->post('surveyid');
			$questiontype_id = $app->request->post('questiontypeid');
			$nextquestion_id = $app->request->post('nextquestionid'); 
			$answer = $app->request->post('answer');

			$data = array( 
							 'question_name'=> $question_name,
							 'question'=> $question,
							 'tag'=> $question_tag,				
							 'question_description'=> $question_description,
							 'nextquestionid'=> $nextquestion_id,
							 'surveyid'=> $surveyid,
							 'questiontypeid' => $questiontype_id,
							 'answer'   => $answer
					);
			$db = new DbHandler();
            $res = $db-> testquestionadmin($data);
            global $user_id;
            $response["error"] = false;
			if ($res == QUESTION_SUCCESSFULLY_CREATED) { 
                $response["error"] = false;
                $response["message"] = "Question successfully created";
            }		
			echoRespnse(200, $response);  
		});

$app->post('/admin/editquestion', function() use ($app) {
            // check for required params
			checkloginuserisadmin();
            verifyRequiredParams(array('id'));
            $response = array();
            // reading post params
			$id = $app->request->post('id');
			$question_name = $app->request->post('name');
            $question = $app->request->post('question');
			$question_tag = $app->request->post('tag');
			$question_description = $app->request->post('description');
			$surveyid = $app->request->post('surveyid');
			$questiontype_id = $app->request->post('questiontypeid');
			$nextquestion_id = $app->request->post('nextquestionid'); 
			$answer = $app->request->post('answer');

			$data = array( 	
							 'id'=> $id,
							 'question_name'=> $question_name,
							 'question'=> $question,
							 'tag'=> $question_tag,				
							 'question_description'=> $question_description,
							 'nextquestionid'=> $nextquestion_id,
							 'surveyid'=> $surveyid,
							 'questiontypeid' => $questiontype_id,
							 'answer'   => $answer
					); 
			$db = new DbHandler();
            $res = $db-> edittestquestionadmin($data);
            global $user_id;
            $response["error"] = false;
			if ($res == QUESTION_SUCCESSFULLY_EDITED) { 
                $response["error"] = false;
                $response["message"] = "Question successfully edited";
            }		
			echoRespnse(200, $response);  
		});


$app->get('/admin/question',$authenticate($app), function() { 
	checkloginuserisadmin();
	global $user_id;
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->getquestionlist();
	
	$response["error"] = false;
	$response["question"] = $result['question'];
	
	//print_r($result);
	/*$response["error"] = false;
	$response["question"] = array();
	// looping through result and preparing tasks array
	while ($question = $result->fetch_array(MYSQLI_ASSOC)) {
		array_push($response["question"], $question);
	}*/
	echoRespnse(200, $response); 
});


$app->post('/admin/deletequestion',$authenticate($app), function() use ($app) {
            // check for required params
			checkloginuserisadmin();
	        verifyRequiredParams(array('id_ques'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id_ques');
            $db   = new DbHandler();
			$data = array('id_ques'=>$id);
			
            $res = $db->deletequestion($data);
			
            if ($res == QUES_DELETED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Question are successfully deleted";
            } else if ($res == QUES_DELETED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while deleting";
            }else if($res ==  QUES_DOESNOT_EXIST){
                $response["error"] = true;
                $response["message"] = "Oops! Question Doenst exist";
   			}else if($res ==  QUES_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! Question Already Deleted";
   			}			
            // echo json response 
            echoRespnse(201, $response);
});



$app->get('/search',$authenticate($app), function() use($app) { 
	$response = array();
	verifyRequiredParams(array('type','page'));
	$type   =  $app->request->get('type');
	$page  =  $app->request->get('page');
	$key  =  $app->request->get('key');
	$db     =  new DbHandler();
	$result =  $db->getsearch($type,$page,$key); 
	
});

$app->get('/admin/list_testsurvey',$authenticate($app), function() { 
			checkloginuserisadmin();
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->list_survey();
	$response["error"] = false;
	$response["survey"] = array();
	// looping through result and preparing tasks array
	while ($pharmacy = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	    = $pharmacy["id"]; 
		$tmp["cod_surv"]    	= $pharmacy["cod_surv"];
		$tmp["surv_name"]   	= $pharmacy["surv_name"]; 
		$tmp["surv_desc"] 		= $pharmacy["surv_desc"];
		$tmp["id_ques_start"]   = $pharmacy["id_ques_start"];
	  
		array_push($response["survey"], $tmp);
	}
	echoRespnse(200, $response); 
});

$app->post('/admin/addtestsurvey', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('cod_surv','surv_name','surv_desc'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			
			$cod_surv = $app->request->post('cod_surv');
            $surv_name = $app->request->post('surv_name');
            $surv_desc = $app->request->post('surv_desc');
            $id_ques_start = $app->request->post('id_ques_start');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
			$data = array(
						  'cod_surv'=>$cod_surv,
						  'surv_name'=>$surv_name,
						  'surv_desc'=>$surv_desc,
						  'id_ques_start'=>$id_ques_start,
						  'id_user_ds' => $id_user_ds,
						  'user_ds_mem' => $user_ds_mem 
						  );
           
            $res = $db->addtestsurvey($data);
            if ($res == TESTSERVEY_ADDED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == TESTSERVEY_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });


$app->post('/admin/edittestsurvey', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_surv'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_surv = $app->request->post('id_surv');
			$cod_surv = $app->request->post('cod_surv');
            $surv_name = $app->request->post('surv_name');
            $surv_desc = $app->request->post('surv_desc');
            $id_ques_start = $app->request->post('id_ques_start');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
			$data = array('id_surv'=>$id_surv,
						  'cod_surv'=>$cod_surv,
						  'surv_name'=>$surv_name,
						  'surv_desc'=>$surv_desc,
						  'id_ques_start'=>$id_ques_start,
						  'id_user_ds' => $id_user_ds,
						  'user_ds_mem' => $user_ds_mem 
						  );
           
            $res = $db->edittestsurvey($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/deletetestsurvey',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_surv'));
            $response = array();
            //reading post params
            $id_surv   = $app->request->post('id_surv');
            $db   = new DbHandler();
			$data = array('id_surv'=>$id_surv);
			
			
            $res = $db->deletetestsurvey($data);
            if ($res == TESTSURVEY_DELETED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == TESTSURVEY_DELETED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/addhistory', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id_surv'));
            $response = array();
			$db = new DbHandler();
			// reading post params
			$id_surv = $app->request->post('id_surv');
			
			$surv = $db->getSurveyById($id_surv);
			$details = $surv->fetch_array(MYSQLI_ASSOC);
			$history_date = date('Y-m-d H:i:s');
            $id_user = $_SESSION['user']['id'];
			$data = array('id_surv'=>$id_surv,
						  'history_date'=>$history_date,
						  'id_user'=>$id_user
						  );
           
            $res = $db->addhistory($data);
            if ($res == HISTORY_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "history successfully added"; 
            } else if ($res == HISTORY_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/edithistory', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_surv'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_surv = $app->request->post('id_surv');
			$history_date = $app->request->post('history_date');
            $id_user = $app->request->post('id_user');
            $survey_key = $app->request->post('survey_key');
			$data = array('id_surv'=>$id_surv,
						  'history_date'=>$history_date,
						  'id_user'=>$id_user,
						  'survey_key'=>$survey_key
						  );
           
            $res = $db->edithistory($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/addhistoryproduct', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id_product'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_product = $app->request->post('id_product');
			$product_order = $app->request->post('product_order');
			$data = array('id_product'=>$id_product,
						  'product_order'=>$product_order
						  );
            
            $res = $db->addhistoryproduct($data);
            if ($res == HISTORYPRODUCT_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORYPRODUCT_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/edithistoryproduct', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_history = $app->request->post('id_history');
			$product_order = $app->request->post('product_order');
			$data = array('id_history'=>$id_history,
						  'product_order'=>$product_order
						  );
           
            $res = $db->edithistoryproduct($data);
            if ($res == HISTORYPRODUCT_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data successfully updated";
            } else if ($res == HISTORYPRODUCT_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/addhistoryproductaddl', $authenticate($app),function() use ($app){
            // check for required params
            //verifyRequiredParams(array('id_product'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_product = $app->request->post('id_product');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_product'=>$id_product,
						  'product_order'=>$product_order
						  );
            
            $res = $db->addhistoryproductaddl($data);
            if ($res == HISTORYPRODUCT_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORYPRODUCT_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/edithistoryproductaddl', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_history = $app->request->post('id_history');
			$id_product = $app->request->post('id_product');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_history'=>$id_history,
						  'id_product'=>$id_product,
						  'product_order'=>$product_order
						  );
           
            $res = $db->edithistoryproductaddl($data);
            if ($res == HISTORYPRODUCT_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data successfully updated";
            } else if ($res == HISTORYPRODUCT_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/addhistoryproductaddl', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            //verifyRequiredParams(array('id_product'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_product = $app->request->post('id_product');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_product'=>$id_product,
						  'product_order'=>$product_order
						  );
            
            $res = $db->addhistoryproductaddl($data);
            if ($res == HISTORYPRODUCT_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORYPRODUCT_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/edithistoryproductaddl', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_history = $app->request->post('id_history');
			$id_product = $app->request->post('id_product');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_history'=>$id_history,
						  'id_product'=>$id_product,
						  'product_order'=>$product_order
						  );
           
            $res = $db->edithistoryproductaddl($data);
            if ($res == HISTORYPRODUCT_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data successfully updated";
            } else if ($res == HISTORYPRODUCT_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });


$app->post('/addhistoryansaddl', $authenticate($app),function() use ($app){
            // check for required params
            //verifyRequiredParams(array('id_product'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_ans = $app->request->post('id_ans');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_ans'=>$id_ans,
						  'product_order'=>$product_order
						  );
            
            $res = $db->addhistoryansaddl($data);
            if ($res == HISTORYPRODUCT_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORYPRODUCT_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/edithistoryansaddl', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_history = $app->request->post('id_history');
			$id_ans = $app->request->post('id_ans');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_history'=>$id_history,
						  'id_ans'=>$id_ans,
						  'product_order'=>$product_order
						  );
           
            $res = $db->edithistoryansaddl($data);
            if ($res == HISTORYPRODUCT_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data successfully updated";
            } else if ($res == HISTORYPRODUCT_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/addhistoryansaddl', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            //verifyRequiredParams(array('id_product'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_ans = $app->request->post('id_ans');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_ans'=>$id_ans,
						  'product_order'=>$product_order
						  );
            
            $res = $db->addhistoryansaddl($data);
            if ($res == HISTORYPRODUCT_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORYPRODUCT_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->post('/admin/edithistoryansaddl', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_history = $app->request->post('id_history');
			$id_ans = $app->request->post('id_ans');
			$product_order = $app->request->post('product_order');
			$data = array(
						  'id_history'=>$id_history,
						  'id_ans'=>$id_ans,
						  'product_order'=>$product_order
						  );
           
            $res = $db->edithistoryansaddl($data);
            if ($res == HISTORYPRODUCT_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "data successfully updated";
            } else if ($res == HISTORYPRODUCT_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });



/*$app->post('/admin/deletehistoryproduct',$authenticate($app), function() use ($app) {
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_history'));
            $response = array();
            //reading post params
            $id_history   = $app->request->post('id_history');
			
            $db   = new DbHandler();
            $res = $db->deletehistoryproduct($id_history);
			
            if ($res == TESTSURVEY_DELETED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == TESTSURVEY_DELETED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
			}else if($res ==  USER_ALREADY_DELETED){
                $response["error"] = true;
                $response["message"] = "Oops! User Already Deleted";
			}
            // echo json response
            echoRespnse(201, $response);
        });
*/


$app->post('/addhistoryans', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id_ans'));
            $response = array();
            // reading post params
			$id_ans = $app->request->post('id_ans');
			
            $db = new DbHandler();
            $res = $db->addhistoryans($id_ans);
            if ($res == HISTORY_ADDED_SUCCESSFULLY) { 
                $response["error"] = false;
                $response["message"] = "data successfully added"; 
            } else if ($res == HISTORY_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while adding";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/*$app->post('/admin/edithistoryans', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('id_surv'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			$id_surv = $app->request->post('id_surv');
			$history_date = $app->request->post('history_date');
            $id_user = $app->request->post('id_user');
            $survey_key = $app->request->post('survey_key');
			$data = array('id_surv'=>$id_surv,
						  'history_date'=>$history_date,
						  'id_user'=>$id_user,
						  'survey_key'=>$survey_key
						  );
           
            $res = $db->edithistoryans($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });
*/


$app->post('/admin/addtestsurvey', $authenticate($app),function() use ($app){
			checkloginuserisadmin();
            // check for required params
            verifyRequiredParams(array('cod_surv','surv_name','surv_desc'));
            $response = array();
			 $db = new DbHandler();
            // reading post params
			
			$cod_surv = $app->request->post('cod_surv');
            $surv_name = $app->request->post('surv_name');
            $surv_desc = $app->request->post('surv_desc');
            $id_ques_start = $app->request->post('id_ques_start');
            $id_user_ds = $app->request->post('id_user_ds');
			$user_ds_mem = $app->request->post('user_ds_mem');
			$data = array(
						  'cod_surv'=>$cod_surv,
						  'surv_name'=>$surv_name,
						  'surv_desc'=>$surv_desc,
						  'id_ques_start'=>$id_ques_start,
						  'id_user_ds' => $id_user_ds,
						  'user_ds_mem' => $user_ds_mem 
						  );
           
            $res = $db->addtestsurvey($data);
            if ($res == TESTSERVEY_ADDED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == TESTSERVEY_ADDED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });


$app->get('/listsurveytag',$authenticate($app),function() use ($app) {
	
	verifyRequiredParams(array('id_surv'));
	$id_surv = $app->request->get('id_surv');
	
	$response = array();
	$db = new DbHandler();
	// fetching all user tasks
	$result = $db->listsurveytag($id_surv);
	$response["error"] = false;
	$response["surveytag"] = array();
	//looping through result and preparing tasks array
	while ($surveytag = $result->fetch_array(MYSQLI_ASSOC)) {
		$tmp = array();
		$tmp["id"]      	=  $surveytag["id"]; 
		$tmp["id_tag"]   	=  $surveytag["id_tag"];
		$tmp["tag_name"]  =  $surveytag["tag_name"];
		array_push($response["surveytag"],$tmp);
	}
	echoRespnse(200, $response); 
});

$app->get('/listtestquestag',$authenticate($app), function() use ($app) { 
			verifyRequiredParams(array('id_ques'));
			$id_ques = $app->request->get('id_ques');
			$response = array();
			$db = new DbHandler();
			// fetching all user tasks
			$result = $db->listtestquestag($id_ques);
			$response["error"] = false;
			$response["test"] = array();
			// looping through result and preparing tasks array
			while ($test = $result->fetch_array(MYSQLI_ASSOC)) {
				$tmp = array();
				$tmp["id_ques_tag"] = $test["id_ques_tag"]; 
				$tmp["id_tag"]   	= $test["id_tag"]; 
				$tmp["tag_name"]  =  $test["tag_name"];
			  
				array_push($response["test"], $tmp);
			}
			echoRespnse(200, $response); 
});

$app->get('/listtestanstag',$authenticate($app), function() use ($app) { 
			checkloginuserisadmin();
			verifyRequiredParams(array('id_ans')); 
			$id_ans = $app->request->get('id_ans');
			$response = array();
			$db = new DbHandler();
			// fetching all user tasks
			$result = $db->listtestanstag($id_ans);
			$response["error"] = false;
			$response["test"] = array();
			// looping through result and preparing tasks array
			while ($test = $result->fetch_array(MYSQLI_ASSOC)) {
				$tmp = array();
				$tmp["id_ans_tag"] = $test["id_ans_tag"]; 
				$tmp["id_tag"]   	= $test["id_tag"]; 
				$tmp["tag_name"]  =  $test["tag_name"];
			  
				array_push($response["test"], $tmp);
			}
			echoRespnse(200, $response); 
});


$app->get('/uploads/:code', function() use($app){
});
/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }
    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}
/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);
    // setting response content type to json
    $app->contentType('application/json');
	$db = new DbHandler();
    echo json_encode($response);
}
		
		
		
/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/tasks/:id', 'authenticate', function($task_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetch task
            $result = $db->getTask($task_id, $user_id);
            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["task"] = $result["task"];
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /tasks/
 */
$app->post('/tasks', 'authenticate', function() use ($app) {
		// check for required params
		verifyRequiredParams(array('task'));
		$response = array();
		$task = $app->request->post('task');
		global $user_id;
		$db = new DbHandler();
		// creating new task
		$task_id = $db->createTask($user_id, $task);
		if ($task_id != NULL) {
			$response["error"] = false;
			$response["message"] = "Task created successfully";
			$response["task_id"] = $task_id;
			echoRespnse(201, $response);
		} else {
			$response["error"] = true;
			$response["message"] = "Failed to create task. Please try again";
			echoRespnse(200, $response);
		}            
	});
	
	
	
	
/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
$app->put('/tasks/:id', 'authenticate', function($task_id) use($app) {
            // check for required params
            verifyRequiredParams(array('task', 'status'));
            global $user_id;            
            $task = $app->request->put('task');
            $status = $app->request->put('status');
            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateTask($user_id, $task_id, $task, $status);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Task updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Task failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });
		
$app->run();
?>