<?php
/*
Plugin Name: Front End Registration and Login
Plugin URI: https://newwebdev.wordpress-developer.us/chp/
Description: Provides simple front end registration and login forms
Version: 1.0
Author: Anit kumar jha
Author URI: https://demo.com
*/
?>
<?php
// user registration login form
function pippin_registration_form() {
 
	// only show the registration form to non-logged-in members  
	if(!is_user_logged_in()) {
 
		global $pippin_load_css;
 
		// set this to true so the CSS is loaded
		$pippin_load_css = true;
 
		// check to make sure user registration is enabled
		$registration_enabled = get_option('users_can_register');
 
		// only show the registration form if allowed
		if($registration_enabled) {
			$output = pippin_registration_form_fields();
		} else {
			$output = __('User registration is not enabled');
		}
		return $output;
	}
}
add_shortcode('register_form', 'pippin_registration_form'); 


// user login form
function pippin_login_form() {
 
	if(!is_user_logged_in()) {
 
		global $pippin_load_css;
 
		// set this to true so the CSS is loaded
		$pippin_load_css = true;
 
		$output = pippin_login_form_fields();
	} else {
		// could show some logged in user info here
		// $output = 'user info here';
	}
	return $output;
}
add_shortcode('login_form', 'pippin_login_form');

function pippin_registration_form_fields() {
 
	ob_start(); ?>	
		
 
		<?php 
		// show any error messages after form submission
		 pippin_show_error_messages(); 
		 //sucess_messages();
		?>
		
		
		
		  <form id="pippin_registration_form" class="pippin_form" action="" method="POST">
                                        <div class="sign-up">
                                            <div class="check">

                                                <div class="form-input form-group">
                                                  <span>*</span>
                                                  <input type="radio" class="styled-checkbox" id="styled-checkbox" name="userrole" value="Buyer" checked="checked">
                                                  <label for="styled-checkbox">Buyer</label>
                                                </div>

                                                <div class="form-input form-group">
                                                    <input type="radio" class="styled-checkbox" id="styled-checkbox2" name="userrole" value="Guest">
                                                    <label for="styled-checkbox2">Guest</label>
                                                </div>

                                                <div class="form-input form-group">
                                                    <input type="radio" class="styled-checkbox" id="styled-checkbox3" name="userrole" value="Agent">
                                                    <label for="styled-checkbox3">Agent</label>
                                                </div>

                                                <div class="form-input form-group">
                                                    <input type="radio" class="styled-checkbox" id="styled-checkbox4" name="userrole" value="FSBO">
                                                    <label for="styled-checkbox4">FSBO</label>
                                                </div>

                                            </div>
                                        </div>

                                        <div class="sign-up-form">
                                            <input name="pippin_user_login" id="pippin_user_login" class="required" type="hidden"/>
                                            <div class="row sign-row">
                                                <div class="col-md-6 sign-col">
                                                    <div class="form-input">
                                                        <label>First name*</label>
                                                        <input name="pippin_user_first" id="pippin_user_first" type="text" required/>
                                                    </div>
													
                                                </div>
                                                <div class="col-md-6 sign-col">
                                                    <div class="form-input">
                                                        <label>Last  name*</label>
                                                       <input name="pippin_user_last" id="pippin_user_last" type="text" required/>
                                                    </div>
                                                </div>

                                                <div class="col-md-12 sign-col">
                                                    <div class="form-input">
                                                        <label>Email*</label>
                                                        <input name="pippin_user_email" id="pippin_user_email" class="required" type="email" required/>
                                                    </div>
                                                </div>

                                                <div class="col-md-12 sign-col">
                                                    <div class="form-input">
                                                        <label>Password*</label>
                                                   <input name="pippin_user_pass" id="password" class="required" type="password" required/>
                                                    </div>
                                                </div>
												
											    <div class="col-md-12 sign-col">
                                                    <div class="form-input">
                                                        <label>Confirm Password*</label>
                                                   <input name="pippin_user_pass_confirm" id="password_again" class="required" type="password" required/>
                                                    </div>
                                                </div>

												

                                                <div class="col-md-12 sign-col">
                                                    <div class="form-input">
                                                        <p>Fields with* must be filled.</p>
                                                        <p>
                                                            By signing up you  agree to Canadian Horse Properties 
                                                            <a href="t&c.html">terms & conditions</a> | <a href="privacy.html">privacy policy</a>.
                                                        </p>
                                                    </div>
                                                </div>

                                            </div>
                                            
                                        </div>

                                        <div class="form-input">
										<input type="hidden" name="pippin_register_nonce" value="<?php echo wp_create_nonce('pippin-register-nonce'); ?>"/>
					                   
                                            <input type="submit" value="Sign Up">
                                        </div>

                                    </form>
 
		
	<?php
	return ob_get_clean();
}

// login form fields
function pippin_login_form_fields() {
 
	ob_start(); ?>
		
 
		<?php
		// show any error messages after form submission
		//pippin_login_show_error_messages();
            
		?>
		
		
		    <form id="pippin_login_form"  class="pippin_form"action="" method="post">
                                        <div class="sign-up-form">

                                            <div class="form-input">
                                                <label>Email*</label>
                                               <input name="pippin_user_login" id="pippin_user_login" class="required" type="text"/>
                                            </div>

                                            <div class="form-input">
                                                <label>Password*</label>
                                               <input name="pippin_user_pass" id="pippin_user_pass" class="required" type="password"/>
                                            </div>
                                        </div>

                                        <div class="form-input">
                                            <input type="hidden" name="pippin_login_nonce" value="<?php echo wp_create_nonce('pippin-login-nonce'); ?>"/>
					                        <input id="pippin_login_submit" type="submit" value="Login"/>
                                        </div>

                                        <div class="form-input">
                                           <p>
                                            Once logged in, you can switch prom a Buyer/Guest account to an Agnet/FSBO
                                            Form your dashboard.
                                           </p>
                                        </div>

                                    </form>
		
		
		

	<?php
	return ob_get_clean();
}

function pippin_login_member() {
 
	if(isset($_POST['pippin_user_login']) && wp_verify_nonce($_POST['pippin_login_nonce'], 'pippin-login-nonce')) {
 
		// this returns the user ID and other info from the user name
		$user = get_userdatabylogin($_POST['pippin_user_login']);
 
		if(!$user) {
			// if the user name doesn't exist
			pippin_errors()->add('empty_username', __('Invalid Email'));
		}
 
		if(!isset($_POST['pippin_user_pass']) || $_POST['pippin_user_pass'] == '') {
			// if no password was entered
			pippin_errors()->add('empty_password', __('Please enter a password'));
		}
 
		// check the user's login with their password
		if(!wp_check_password($_POST['pippin_user_pass'], $user->user_pass, $user->ID)) {
			// if the password is incorrect for the specified user
			pippin_errors()->add('empty_password', __('Incorrect password'));
		}
 
		// retrieve all error messages
		$errors3 = pippin_errors()->get_error_messages();
 
		// only log the user in if there are no errors
		if(empty($errors3)) {
 
			wp_setcookie($_POST['pippin_user_login'], $_POST['pippin_user_pass'], true);
			wp_set_current_user($user->ID, $_POST['pippin_user_login']);	
			do_action('wp_login', $_POST['pippin_user_login']);
 
			wp_redirect(home_url()); exit;
		}
	}
}
add_action('init', 'pippin_login_member');


// register a new user
function pippin_add_new_member() {
  	if (isset( $_POST["pippin_user_login"] ) && wp_verify_nonce($_POST['pippin_register_nonce'], 'pippin-register-nonce')) {
		$user_login		= $_POST["pippin_user_first"].'_'.$_POST["pippin_user_last"];	
		$user_email		= $_POST["pippin_user_email"];
		$user_first 	= $_POST["pippin_user_first"];
		$user_last	 	= $_POST["pippin_user_last"];
		$user_pass		= $_POST["pippin_user_pass"];
		$pass_confirm 	= $_POST["pippin_user_pass_confirm"];
		$userrole 	=     $_POST["userrole"];
		
		
 
		// this is required for username checks
		require_once(ABSPATH . WPINC . '/registration.php');
 
		if(username_exists($user_login)) {
			// Username already registered
			pippin_errors()->add('username_unavailable', __('Username already taken'));
		}
		if(!validate_username($user_login)) {
			// invalid username
			pippin_errors()->add('username_invalid', __('Invalid username'));
		}
		if($user_login == '') {
			// empty username
			pippin_errors()->add('username_empty', __('Please enter a username'));
		}
		if(!is_email($user_email)) {
			//invalid email
			pippin_errors()->add('email_invalid', __('Invalid email'));
		}
		if(email_exists($user_email)) {
			//Email address already registered
			pippin_errors()->add('email_used', __('Email already registered'));
		}
		if($user_pass == '') {
			// passwords do not match
			pippin_errors()->add('password_empty', __('Please enter a password'));
		}
		if($user_pass != $pass_confirm) {
			// passwords do not match
			pippin_errors()->add('password_mismatch', __('Passwords do not match'));
		}
 
		$errors = pippin_errors()->get_error_messages();
 
		// only create the user in if there are no errors
		if(empty($errors)) {
 
			$new_user_id = wp_insert_user(array(
					'user_login'		=> $user_login,
					'user_pass'	 		=> $user_pass,
					'user_email'		=> $user_email,
					'first_name'		=> $user_first,
					'last_name'			=> $user_last,
					'user_registered'	=> date('Y-m-d H:i:s'),
					'role'				=> strtolower($userrole)
				)
			);
			if($new_user_id) {
				// send an email to the admin alerting them of the registration
				wp_new_user_notification($new_user_id);
 
				// log the new user in
				//wp_setcookie($user_login, $user_pass, true);
				//wp_set_current_user($new_user_id, $user_login);	
				//do_action('wp_login', $user_login);
				$msg=md5('reg');
				// send the newly created user to the home page after logging them in
				wp_redirect(home_url().'/login/?msg='.$msg); exit;
			}
 
		}
 
	}
}
add_action('init', 'pippin_add_new_member');

// used for tracking error messages
function pippin_errors(){
    static $wp_error; // Will hold global variable safely
    return isset($wp_error) ? $wp_error : ($wp_error = new WP_Error(null, null, null));
}

// displays error messages from form submissions
function pippin_show_error_messages() {
	if($codes = pippin_errors()->get_error_codes()) {
		echo '<div class="pippin_errors">';
		    // Loop error codes and display errors
		   foreach($codes as $code){
		        $message = pippin_errors()->get_error_message($code);
		        echo '<span class="error"><strong>' . __('Error') . '</strong>: ' . $message . '</span><br/>';
		    }
		echo '</div>';
	}	
}

