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

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
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
                    $response['created'] = $user['version_date'];
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
	session_destroy();
	$app->view()->setData(array('session' => false));
	$app->render('logout.php');
});

/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password'));
            $response = array();
            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
			
			$data = array(
						  'name'=>$name,
						  'email'=>$email,
						  'password'=>$password,
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
		
		
$app->post('/edituser',$authenticate($app), function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name'));
            $response = array();
            //reading post params
            $name = $app->request->post('name');
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('name'=>$name,'id'=>$id);
			
			
            $res = $db->userAction($data,'edit');
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
		
$app->post('/deleteuser',$authenticate($app), function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
            $db   = new DbHandler();
			$data = array('id'=>$id);
			
			
            $res = $db->userAction($data,'delete');
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user are successfully deleted";
            } else if ($res == USER_UPDATED_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
		

/*
  * Listing all tasks of particual user
  * method GET
  * url /tasks          
*/
$app->get('/users',$authenticate($app), function() {
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
$app->post('/qrimage',function() use ($app){
            verifyRequiredParams(array('email'));
            // reading post params
            $email = $app->request()->post('email');
            $response = array();
            $db = new DbHandler();
            // check for correct email and password
            if ($db->isUserExists($email)) { 
                    $response["error"] = false;
					$qrimage = $db->qrgenerator($email);
                    $response["pharmacist"] = $qrimage["pharmacist"];
                    $response["customer"] = $qrimage["customer"];
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'User doesn\'t exist';
            }
            echoRespnse(200, $response);
        });

		

		

/**
 * Listing all tasks of particual user
 * method GET
 * url admin/users          
 */
$app->get('/admin/users',$authenticate($app), function() {
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
 * Add user by admin 
 * method POST
 * url v1/admin/adduser          
 */
$app->post('/admin/adduser',$authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password'));
            $response = array();
            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $type = $app->request->post('type');
			$data = array( 
						  'name'=>$name,
						  'email'=>$email,
						  'password'=>$password,
						  'type'=>$type,
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
            // check for required params
            verifyRequiredParams(array('id', 'name'));
            $response = array();
            // reading post params
            $name = $app->request->post('name');
            $id = $app->request->post('id');
			$data = array( 
						  'name'=>$name,
						  'id'=>$id,
						  );
            $db = new DbHandler();
            $res = $db->updateUser($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		

$app->post('/admin/edituser', $authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id', 'name'));
            $response = array();
            // reading post params
            $name = $app->request->post('name');
            $id = $app->request->post('id');
			$data = array( 
						  'name'=>$name,
						  'id'=>$id,
						  );
            $db = new DbHandler();
            $res = $db->updateUser($data);
            if ($res == USER_UPDATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "user successfully updated";
            } else if ($res == USER_UPDATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while updating";
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
		
	
/**
 * Add Pharmacist by admin 
 * method POST
 * url v1/admin/addpharmacist 
 * prameter for post or get   parameter  URL,authenticate ,function         
 */
$app->post('/admin/addpharmacy',$authenticate($app),function() use ($app){
            // check for required params
            verifyRequiredParams(array('id', 'name', 'phone', 'address1','zip','town','email'));
            $response = array();
            // reading post params address1,address2,zip,town,latitude,longitude,phone,url,status
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
			$version_date   = $app->request->post('version_date');
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
						  'version_date' =>$version_date,
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
            verifyRequiredParams(array('id'));
            $response = array();
			$id = $app->request->post('id');
			$data = array('id'=>$id);
            $db = new DbHandler();
            // fetching all user tasks  
            $result = $db->infopharma($data);
			global $user_id;
            $response["error"] = false;
            $response["details"] = array();
            // looping through result and preparing tasks array
            while ($details = $result->fetch_array(MYSQLI_ASSOC)) {
                $tmp = array();
                $tmp["user_id"]      	   = $details["id"];
				$tmp["id_pharmacy"]        = $details["id_pharmacy"];
				$tmp["user_name"]    	   = $details["pharmacy_name"];
				$tmp["id_group"]   	  	   = $details["id_group"];
                $tmp["pharmacy_addr1"]     = $details["pharmacy_addr1"];
                $tmp["pharmacy_addr2"]     = $details["pharmacy_addr2"];
                $tmp["pharmacy_zip"]       = $details["pharmacy_zip"];
                $tmp["pharmacy_city"] 	   = $details["pharmacy_city"];
                $tmp["pharmacy_latitude"]  = $details["pharmacy_latitude"];
				$tmp["user_email"]   	   = $details["pharmacy_email"];
				$tmp["pharmacy_phone"]     = $details["pharmacy_phone"];
                $tmp["pharmacist_name"]    = $details["pharmacist_name"];
				$tmp["active"]       	   = $details["pharmacy_active"];
                $tmp["version"]      	   = $details["version"];
				$tmp["id_user_version"]    = $details["id_user_version"];
                $tmp["version_date"] 	   = $details["version_date"];
                $tmp["pharmacy_longitude"] = $details["pharmacy_longitude"];
                
                array_push($response["details"], $tmp);
            }
            echoRespnse(200, $response);  
		});

		
$app->post('/admin/editpharmacy', $authenticate($app),function() use ($app){
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
			$version_date   = $app->request->post('version_date');
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
						  'version_date' =>$version_date,
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
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->post('/admin/addpharmacyday', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id', 'day_start_time', 'day_end_time','email'));
            $response = array();
            // reading post params
            $id = $app->request->post('id');
			$email = $app->request->post('email');
			$idday = $app->request->post('idday');
            $starttime = $app->request->post('day_start_time');
            $endtime = $app->request->post('day_end_time');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
            $versiondate = $app->request->post('versiondate');
			
			$data = array(
						  'id'=>$id,
						  'email'=>$email,
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
            // check for required params
            verifyRequiredParams(array('id','day_start_time','day_end_time'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
			$daystarttime = $app->request->post('day_start_time');
			$dayendtime = $app->request->post('day_end_time');
            $db   = new DbHandler();
			$data = array('daystarttime'=>$daystarttime,'id'=>$id,'dayendtime'=>$dayendtime);
			
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
            }
            // echo json response
            echoRespnse(201, $response);
        });
		
$app->get('/admin/listpharmacyday',$authenticate($app), function() {
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

$app->post('/admin/addpharmacylaboratory', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('laboratory_start_date', 'laboratory_end_date','email'));
            $response = array();
            // reading post params
			$laboratoryid = $app->request->post('laboratoryid');
            $startday = $app->request->post('laboratory_start_date');
            $endday = $app->request->post('laboratory_end_date');
			$email = $app->request->post('email');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
            $versiondate = $app->request->post('versiondate');
			
			$data = array(
						  'laboratoryid'=>$laboratoryid,
						  'startday'=>$startday,
						  'endday'=>$endday,
						  'email'=>$email,
						  'version'=>$version,
						  'iduserversion'=>$iduserversion,
						  'versiondate'=>$versiondate,
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
            // check for required params
            verifyRequiredParams(array('id','laboratory_start_date','laboratory_end_date'));
            $response = array();
            //reading post params
            $id   = $app->request->post('id');
			$startday = $app->request->post('laboratory_start_date');
			$endday = $app->request->post('laboratory_end_date');
            $db   = new DbHandler();
			$data = array('startday'=>$startday,'id'=>$id,'endday'=>$endday);
			
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
            }
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listpharmacylaboratory',$authenticate($app), function() {
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
		

$app->post('/admin/addpharmacyrole', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id_role','pharmacy_role_start_date', 'pharmacy_role_end_date','email'));
            $response = array();
            // reading post params
			$id_user = $app->request->post('id_user');
            $id_role = $app->request->post('id_role');
            $pharmacy_role_start_date = $app->request->post('pharmacy_role_start_date');
			$pharmacy_role_end_date = $app->request->post('pharmacy_role_end_date');
            $version = $app->request->post('version');
			$iduserversion = $app->request->post('iduserversion');
            $versiondate = $app->request->post('versiondate');
			$email = $app->request->post('email');
			
			$data = array(
						  'id_user'=>$id_user,
						  'id_role'=>$id_role,
						  'pharmacy_role_start_date'=>$pharmacy_role_start_date,
						  'pharmacy_role_end_date'=>$pharmacy_role_end_date,
						  'version'=>$version,
						  'iduserversion'=>$iduserversion,
						  'versiondate'=>$versiondate,
						  'email'=>$email
						  );
            $db = new DbHandler();
            $res = $db->addpharmacyrole($data);
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
		
$app->post('/admin/editpharmacyrole',$authenticate($app), function() use ($app) {
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
            }
            // echo json response 
            echoRespnse(201, $response);
        });

$app->get('/admin/listpharmacyrole',$authenticate($app), function() {
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
		
$app->post('/admin/addproduct', function() use ($app) {
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
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			$version_date = $app->request->post('version_date');
			
			$data = array(
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
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
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
			$version_date = $app->request->post('version_date');
			
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
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
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
            }
            // echo json response 
            echoRespnse(201, $response);
        });
		 
$app->get('/admin/listproduct',$authenticate($app), function() { 
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

$app->post('/admin/addproducttag', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id_product','id_tag', 'product_tag_score'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $id_tag = $app->request->post('id_tag');
            $product_tag_score = $app->request->post('product_tag_score');
			$product_tag_active = $app->request->post('product_tag_active');
			$version = $app->request->post('version');
			$id_user_version = $app->request->post('id_user_version');
			$version_date = $app->request->post('version_date');
			
			$data = array(
						  'id_product'=>$id_product,
						  'id_tag'=>$id_tag,
						  'product_tag_score'=>$product_tag_score,
						  'product_tag_active'=>$product_tag_active,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
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
/*vikas */

$app->post('/admin/product_composition', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('id_product','id_ingredient', 'product_ingredient_active','version','id_user_version','version_date'));
            $response = array();
            // reading post params
			$id_product = $app->request->post('id_product');
            $id_ingredient = $app->request->post('id_ingredient');
            $product_ingredient_active = $app->request->post('product_ingredient_active');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			$version_date = $app->request->post('version_date');
          
			
			$data = array(
						  'id_product'=>$id_product,
						  'id_ingredient'=>$id_ingredient,
						  'product_ingredient_active'=>$product_ingredient_active,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
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
            // check for required params
            verifyRequiredParams(array('id_product','id_ingredient', 'product_ingredient_active','version','id_user_version','version_date'));
            $response = array();
            //reading post params
		$id_product = $app->request->post('id_product');
            $id_ingredient = $app->request->post('id_ingredient');
            $product_ingredient_active = $app->request->post('product_ingredient_active');
			$version = $app->request->post('version');
            $id_user_version = $app->request->post('id_user_version');
			$version_date = $app->request->post('version_date');
			
           
			$data = array(
						  'id_product'=>$id_product,
						  'id_ingredient'=>$id_ingredient,
						  'product_ingredient_active'=>$product_ingredient_active,
						  'version'=>$version,
						  'id_user_version'=>$id_user_version,
						  'version_date'=>$version_date
						  );
            $db = new DbHandler();
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
            }
            // echo json response 
            echoRespnse(201, $response);
        });
		 
$app->get('/admin/listproduct',$authenticate($app), function() { 
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
				$tmp["id_laboratory"]   	 = $pharmacy["id_ingredient"];
                $tmp["version"]   = $pharmacy["version"];
                $tmp["id_user_version"] 	 = $pharmacy["id_user_version"];
               	$tmp["version_date"]       	 = $pharmacy["version_date"];
                array_push($response["pharmacy"], $tmp);
            }
            echoRespnse(200, $response); 
		});
		
$app->run();
?>