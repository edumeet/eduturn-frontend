<?php
use Hackzilla\PasswordGenerator\Generator\ComputerPasswordGenerator;
require_once('/usr/share/simplesamlphp/lib/_autoload.php');
require_once('vendor/autoload.php');
require_once('Db.php');
$as = new SimpleSAML_Auth_Simple('default-sp');
$as->requireAuth();
$attributes = $as->getAttributes();
//print_r($attributes);
$logout_url='https://brain.lab.vvc.niif.hu/';
//connectdb
$db_rest = Db::Connection("coturn-rest");
$db_ltc = Db::Connection("coturn-ltc");

//create csfr token
session_start();
if (empty($_SESSION['token'])) {
    if (function_exists('mcrypt_create_iv')) {
        $_SESSION['token'] = bin2hex(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
    } else {
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}
$token = $_SESSION['token'];

if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest' && !empty($_POST)) {
    // AJAX request
    if (!empty($_POST['token'])) {
        if (hash_equals($_POST['token'], $_SESSION['token'])) { 
            switch($_POST["form"]){
                case "feedback":
                    $mail = new PHPMailer;
                    //$mail->SMTPDebug = 3;                               // Enable verbose debug output
                    
                    $mail->isSMTP();                                      // Set mailer to use SMTP
                    $mail->Host = 'localhost';  // Specify main and backup SMTP servers
                
                    $mail->CharSet = "UTF-8";
                    
                    $mail->setFrom('video-admin@niif.hu', 'Contact Webform');
                    // set recipient
                    $mail->addAddress('video-admin@niif.hu', 'Voice Video Collaboration');     // Add a recipient
                    
                    $mail->isHTML(true);                                  // Set email format to HTML
                    
                    $mail->Subject = 'Contact Form from brain.lab.vvc.niif.hu';
                    $mail->Body    = "Name: ".$_POST['Name']."<br>Email: ".$_POST['Email']."<br>Phone: ".$_POST['Phone']."<br>Message:".$_POST['Message'];
                    $mail->AltBody = "Name: ".$_POST['Name']."\nEmail: ".$_POST['Email']."\nPhone: ".$_POST['Phone']."\nMessage:".$_POST['Message'];
                    
                    if(!$mail->send()) {
                        http_response_code(500);
                        echo 'Message could not be sent.';
                        echo 'Mailer Error: ' . $mail->ErrorInfo;
                    } else {
                        echo 'Message has been sent';
                        // We delete the addresses of distributer and owner.
                        $mail->ClearAddresses();
                        
                        $mail->addAddress($_POST['Email'], $_POST['Name']);     // Add a recipient
                        $mail->Subject = 'Your feedback is highly Appreciated!';
                        $mail->Body = "Many thanks for Your feedback, we will contact you soon..<br><br>Lab Team";
                    	$mail->AltBody = "Many thanks for Your feedback, we will contact you soon..\n\nLab Team";
                        
                        if($mail->Send()){  }else{ $error = "Error sending feedback message to the user! <br/>"; }
                    }
                    break;
                case "renewpassword":
                    $generator = new ComputerPasswordGenerator();
                    
                    $generator
                      ->setUppercase()
                      ->setLowercase()
                      ->setNumbers()
                      ->setSymbols(false)
                      ->setLength(16);
                    
                    $password = $generator->generatePasswords();
                    break;
                case "addservice":
                    $generator = new ComputerPasswordGenerator();
                    
                    $generator
                      ->setUppercase(false)
                      ->setLowercase()
                      ->setNumbers()
                      ->setSymbols(false)
                      ->setLength(32);
                    $token = $generator->generatePasswords();
        	    
        	    $query="INSERT INTO token (eppn,email,displayname,token,service_url) values(:eppn,:mail,:displayname,:token[0],:service_url)";
                    $sth = $db_rest->prepare($query);
                    $sth->bindValue(':eppn', $attributes["eduPersonPrincipalName"][0], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attributes["mail"][0], PDO::PARAM_STR);
                    $sth->bindValue(':displayname', $attributes["displayName"][0], PDO::PARAM_STR);
                    $sth->bindValue(':token', $token[0], PDO::PARAM_STR);
                    $sth->bindValue(':service_url', $_POST['service_url'], PDO::PARAM_STR);
                    if($sth->execute()){
        		//success
        	    } else {
        		http_response_code(500);
        		echo $query;
        		echo 'New service could not be inserted.';
        	    }
                    break;
            }
        }
    } 
} else {
?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>STUN/TURN pilot</title>
    <meta name="description" content="STUN/TURN federation" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/bootstrap.min.css" />
    <link rel="stylesheet" href="css/animate.min.css"  />
    <link rel="stylesheet" href="css/ionicons.min.css" />
    <link rel="stylesheet" href="css/styles.css" />
  </head>
  <body>
    <nav id="topNav" class="navbar navbar-default navbar-fixed-top">
        <div class="container-fluid">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-navbar">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand page-scroll" href="https://vvc.niif.hu/en/node/64"><i class="ion-ios-flask-outline"></i> NIIF VVC Laboratory</a>
            </div>
            <div class="navbar-collapse collapse" id="bs-navbar">
                <ul class="nav navbar-nav">
                    <li>
                        <a class="page-scroll" href="#one">Intro</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#two">Password</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#three">REST API</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#four">Oauth</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#last">Contact</a>
                    </li>
                    <li>
                        <a href="logout.php">Logout</a>
                    </li>
                 </ul>
                <ul class="nav navbar-nav navbar-right">
                    <li>
                        <a class="page-scroll" data-toggle="modal" title="A free Bootstrap video landing theme" href="#aboutModal">About</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <header id="first">
        <div class="header-content">
            <div class="inner">
                <h1 style="visibility: visible; animation-name: flipInX;" class="cursive wow flipInX">STUN/TURN federation pilot</h1>
                <h4>A federated joint effort to build STUN/TURN infrastructure for ICE (Interactive Connectivity Establishment) agents.</h4>
                <hr>
                <a href="#video-background" id="toggleVideo" data-toggle="collapse" class="btn btn-primary btn-xl">Toggle Video</a> &nbsp; <a href="#one" class="btn btn-primary btn-xl page-scroll">Get Started</a>
            </div>
        </div>
        <video style="visibility: visible; animation-delay: 0.5s; animation-name: fadeIn;" autoplay="autoplay" loop="" class="fillWidth fadeIn wow collapse in" data-wow-delay="0.5s" poster="img/Traffic-blurred2.jpg" id="video-background">
            <source src="/video/Traffic-blurred2.mp4" type="video/mp4">Your browser does not support the video tag. I suggest you upgrade your browser.
        </video>
    </header>
    <section class="bg-primary" id="one">
        <div class="container">
            <div class="row">
                <div class="col-lg-6 col-lg-offset-3 col-md-8 col-md-offset-2 text-center">
                    <h2 class="margin-top-0 text-primary">Welcome to STUN/TURN pilot</h2>
                    <br>
                    <p class="text-faded">
                       Lorem ipsum dolor sit amet, ei sed tale appetere, at quo nonumes dissentias. Decore praesent sed et, sit id summo invenire efficiendi. Et mei commodo sententiae, vis an aeterno complectitur, elitr audire pro in. Sit sumo mutat epicuri ea, minim integre his cu. Ne his ridens docendi, ut vis noster audire. 
                    </p>
                    <a href="#six" class="btn btn-default btn-xl page-scroll">Learn More</a>
                </div>
            </div>
        </div>
    </section>
    <section id="two">
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">Password</h2>
                    <h3>Long Term Credential Mechanism</h3>
                    <hr class="primary">
                </div>
            </div>
        </div>
        <div class="container">
            <div class="row col-md-8 col-md-offset-2 custyle">
            <a href="#" class="btn btn-primary btn-xs pull-right"><b>+</b> Add new realm</a>
            <table class="table">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Realm</th>
                    <th>MD5(username:realm:password)</th>
                    <th class="text-center">Action</th>
                </tr>
            </thead>
<?php       
$query="SELECT * FROM turnusers_lt where eppn=:eppn'";
$sth->bindValue(':eppn', $attributes["eduPersonPrincipalName"][0], PDO::PARAM_STR);
$sth = $db_ltc->prepare($query);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);
foreach ($result as $row => $columns) {
echo"                    <tr>
                        <td>".$columns["name"]."</td>
                        <td>".$columns["realm"]."</td>
                        <td>".$columns["hmackey"]."</td>
                        <td class=\"text-center\"><a class='btn btn-primary btn-xs' href=\"#\"><span class=\"ion-android-refresh\"></span> Renew</a> <a href=\"#\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-delete\"></span> Del</a></td>
                    </tr>\n";
}
?>
           </table>
            </div>
        </div>
        <div class="container">
            <div class="row">
                <div class="col-lg-4 col-md-4 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.3s; animation-name: none;" class="icon-lg ion-ios-telephone-outline wow fadeIn" data-wow-delay=".3s"></i>
                        <h3>Legacy</h3>
                        <p class="text-muted">For legacy Soft/Hard phones and VC systems</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-4 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.2s; animation-name: none;" class="icon-lg ion-ios-locked-outline wow fadeInUp" data-wow-delay=".2s"></i>
                        <h3>Secure</h3>
                        <p class="text-muted">Protection against dictionary attacks</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-4 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.3s; animation-name: none;" class="icon-lg ion-android-cloud-outline wow fadeIn" data-wow-delay=".3s"></i>
                        <h3>Distributed</h3>
                        <p class="text-muted">The Service is distributed around Europe</p>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <section class="bg-dark" id="three">
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">REST API</h2>
                    <h3>Time Limited Long Term Credential Mechanism</h3>
                    <hr class="primary">
                </div>
            </div>
        </div>
        <div class="container text-center">
            <div class="call-to-action">
                <h2 style="visibility: hidden; animation-name: none;" class="text-primary">Get Started</h2>
                <a href="/restapi" target="ext" class="btn btn-default btn-lg wow flipInX">The REST API Documentation</a>
            </div>
         </div>       
        <div class="container" id="tokens">
            <div class="row col-md-8 col-md-offset-2 custyle" id="token_table">
            <a href="#addServiceModal" data-toggle="modal" data-target="#addServiceModal" class="btn btn-primary btn-xs pull-right"><b>+</b> Add new service</a>
            <table class="table">
            <thead>
                <tr>
                    <th>Token (api_key)</th>
                    <th>Service URL</th>
                    <th>Realm</th>
                    <th>Expire</th>
                    <th class="text-center">Action</th>
                </tr>
            </thead>
<?php       
$query="SELECT token,service_url,realm,(created + INTERVAL 1 YEAR) as expire FROM token where eppn=:eppn'";
$sth->bindValue(':eppn', $attributes["eduPersonPrincipalName"][0], PDO::PARAM_STR);
$sth = $db_rest->prepare($query);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);
foreach ($result as $row => $columns) {
echo"                    <tr>
                        <td>".$columns["token"]."</td>
                        <td>".$columns["service_url"]."</td>
                        <td>".$columns["realm"]."</td>
                        <td>".$columns["expire"]."</td>
                        <td class=\"text-center\"><a class='btn btn-primary btn-xs' href=\"#\"><span class=\"ion-android-refresh\"></span> Renew</a> <a href=\"#\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-delete\"></span> Del</a></td>
                    </tr>";
}
?>
           </table>
            </div>
        </div>
         <div class="container">
            <div class="row">
                <div class="col-lg-3 col-md-3 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.3s; animation-name: none;" class="icon-lg ion-social-chrome-outline wow fadeIn" data-wow-delay=".3s"></i>
                        <h3>WebRTC</h3>
                        <p class="text-muted">Designed for WebRTC usage</p>
                    </div>
                </div>
                <div class="col-lg-3 col-md-3 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.2s; animation-name: none;" class="icon-lg ion-ios-locked-outline wow fadeInUp" data-wow-delay=".2s"></i>
                        <h3>Secure</h3>
                        <p class="text-muted">Protection against many attacks</p>
                    </div>
                </div>
                <div class="col-lg-3 col-md-3 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.3s; animation-name: none;" class="icon-lg ion-arrow-swap wow fadeIn" data-wow-delay=".3s"></i>
                        <h3>Compatibility</h3>
                        <p class="text-muted">Client side backward compatibility</p>
                    </div>
                </div>
                <div class="col-lg-3 col-md-3 text-center">
                    <div class="feature">
                        <i style="visibility: hidden; animation-delay: 0.3s; animation-name: none;" class="icon-lg ion-android-cloud-outline wow fadeIn" data-wow-delay=".3s"></i>
                        <h3>Distributed</h3>
                        <p class="text-muted">Distributed around Europe</p>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <section id="four">
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">OAUTH</h2>
                    <h3>Third Party Authorization Mechanism</h3>
                    <hr class="primary">
                    <h1>It is in the pipe<hr> comming soon...</h1>
                </div>
            </div>
        </div>
    </section>
    <section id="five" class="no-padding">
        <div class="container-fluid">
            <div class="row no-gutter">
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-002.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-002.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-003.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-003.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-004.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-004.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-005.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-005.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-006.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-006.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-007.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-007.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-008.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-008.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-009.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-009.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-010.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-010.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                 <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-013.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-013.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-014.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-014.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-015.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-015.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-87-behave-10/slides-87-behave-10-page-016.jpg">
                        <img src="img/slides-87-behave-10/slides-87-behave-10-page-016.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-90-tram-6/slides-90-tram-6-page-004.jpg">
                        <img src="img/slides-90-tram-6/slides-90-tram-6-page-004.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
                <div class="col-lg-4 col-sm-6">
                    <a href="#galleryModal" class="gallery-box" data-toggle="modal" data-src="img/slides-90-tram-6/slides-90-tram-6-page-011.jpg">
                        <img src="img/slides-90-tram-6/slides-90-tram-6-page-011.jpg" class="img-responsive" alt="Image 1">
                        <div class="gallery-box-caption">
                            <div class="gallery-box-content">
                                <div>
                                    <i class="icon-lg ion-ios-search"></i>
                                </div>
                            </div>
                        </div>
                    </a>
                </div>
             </div>
        </div>
    </section>
    <section class="container-fluid" id="six">
        <div class="row">
            <div class="col-xs-10 col-xs-offset-1 col-sm-6 col-sm-offset-3 col-md-4 col-md-offset-4">
                <h2 class="text-center text-primary">Features</h2>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>Simple</h3>
                    <div class="media-body media-middle">
                        <p>What could be easier? Get started fast with this landing page starter theme.</p>
                    </div>
                    <div class="media-right">
                        <i class="icon-lg ion-ios-bolt-outline"></i>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeIn">
                    <h3>Free</h3>
                    <div class="media-left">
                        <a href="#alertModal" data-toggle="modal" data-target="#alertModal"><i class="icon-lg ion-ios-cloud-download-outline"></i></a>
                    </div>
                    <div class="media-body media-middle">
                        <p>Yes, please. Grab it for yourself, and make something awesome with this.</p>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>Unique</h3>
                    <div class="media-body media-middle">
                        <p>Because you don't want your Bootstrap site, to look like a Bootstrap site.</p>
                    </div>
                    <div class="media-right">
                        <i class="icon-lg ion-ios-snowy"></i>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeIn">
                    <h3>Popular</h3>
                    <div class="media-left">
                        <i class="icon-lg ion-ios-heart-outline"></i>
                    </div>
                    <div class="media-body media-middle">
                        <p>There's good reason why Bootstrap is the most used frontend framework in the world.</p>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>Tested</h3>
                    <div class="media-body media-middle">
                        <p>Bootstrap is matured and well-tested. It's a stable codebase that provides consistency.</p>
                    </div>
                    <div class="media-right">
                        <i class="icon-lg ion-ios-flask-outline"></i>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <aside class="bg-dark">
        <div class="container text-center">
            <div class="call-to-action">
                <h2 style="visibility: hidden; animation-name: none;" class="text-primary">Get Started</h2>
                <a href="http://coturn.net" target="ext" class="btn btn-default btn-lg wow flipInX">This Service is based on: COTURN</a>
            </div>
            <br>
            <hr>
            <br>
            <div class="row">
                <div class="col-lg-10 col-lg-offset-1">
                    <div class="row">
                        <h6 class="wide-space text-center">THE SERVICE IS BASED ON OPEN STANDARDS</h6>
                        <div class="col-sm-3 col-xs-6 text-center">
                            <i class="icon-lg ion-social-tux" title="Debian Linux"></i>
                        </div>
                        <div class="col-sm-3 col-xs-6 text-center">
                            <i class="icon-lg ion-ios-paper-outline" title="IETF Open Standards"></i>
                        </div>
                        <div class="col-sm-3 col-xs-6 text-center">
                            <i class="icon-lg ion-ribbon-b" title="Standards"></i>
                        </div>
                        <div class="col-sm-3 col-xs-6 text-center">
                            <i class="icon-lg ion-social-html5-outline" title="html 5"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </aside>
    <section id="last">
        <div class="container">
            <div class="row">
                <div class="col-lg-8 col-lg-offset-2 text-center">
                    <h2 style="visibility: hidden; animation-name: none;" class="margin-top-0 wow fadeIn">Get in Touch</h2>
                    <hr class="primary">
                    <p>We love feedback. Fill out the form below and we'll get back to you as soon as possible.</p>
                </div>
                <div class="col-lg-10 col-lg-offset-1 text-center">
                    <form class="contact-form row" id="contact-form" method="post">
			<input type="hidden" name="token" value="<?php echo $token; ?>" />		
                        <input type="hidden" name="form" value="feedback">
                        <div class="col-md-4">
                            <label></label>
                            <input class="form-control" placeholder="Name" type="text" name="Name" value="<?php echo $attributes['displayName'][0];?>">
                        </div>
                        <div class="col-md-4">
                            <label></label>
                            <input class="form-control" placeholder="Email" type="text" name="Email" value="<?php echo $attributes['mail'][0];?>">
                        </div>
                        <div class="col-md-4">
                            <label></label>
                            <input class="form-control" placeholder="Phone" name="Phone" type="text">
                        </div>
                        <div class="col-md-12">
                            <label></label>
                            <textarea class="form-control" rows="9" id="contact-form-message" name="Message" placeholder="Your message here.."></textarea>
                        </div>
                        <div class="col-md-4 col-md-offset-4">
                            <label></label>
                            <button type="submit" class="btn btn-primary btn-block btn-lg">Send <i class="ion-android-arrow-forward"></i></button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </section>
    <footer id="footer">
        <div class="container-fluid">
            <div class="row">
                <div class="col-xs-6 col-sm-3 column">
                    <h4>Information</h4>
                    <ul class="list-unstyled">
                        <li><a href="https://www.assembla.com/spaces/gn4-webrtc/">Assembla</a></li>
                        <li><a href="https://wiki.geant.org/display/SA8/GN4+SA8+Internal+Wiki">Wiki</a></li>
                        <li><a href="https://intranet.geant.org/gn4/1/Activities/SA8/SitePages/Home.aspx">GÉANT SA8</a></li>
                        <li><a href="https://wiki.geant.org/display/WRTC/TF-WebRTC+Task+Force+on+WebRTC">TF-WebRTC</a></li>
                     </ul>
                </div>
                <div class="col-xs-6 col-sm-3 column">
                    <h4>About</h4>
                    <ul class="list-unstyled">
                        <li><a href="mailto:gn4-1-webrtc@lists.geant.org">Contact Us</a></li>
                        <li><a href="mailto:gn4-1-webrtc@lists.geant.org?subject=Technical Support">Support</a></li>
                        <li><a href="privacy.html">Privacy Policy</a></li>
                        <li><a href="terms.html">Terms &amp; Conditions</a></li>
                    </ul>
                </div>
                <div class="col-xs-12 col-sm-3 column">
                    <h4>Stay Posted</h4>
                    <form>
                        <div class="form-group">
                          <input type="hidden" name="token" value="<?php echo $token; ?>" />
                          <input class="form-control" title="No spam, we promise!" placeholder="Tell us your email" type="text">
                        </div>
                        <div class="form-group">
                          <button class="btn btn-primary" data-toggle="modal" data-target="#alertModal" type="button">Subscribe for updates</button>
                        </div>
                    </form>
                </div>
                <div class="col-xs-12 col-sm-3 text-right">
                    <h4>Follow</h4>
                    <ul class="list-inline">
                      <li><a rel="nofollow" href="http://twitter.com/GEANTnews" title="Twitter"><i class="icon-lg ion-social-twitter-outline"></i></a>&nbsp;</li>
                      <li><a rel="nofollow" href="http://www.facebook.com/GEANTnetwork" title="Facebook"><i class="icon-lg ion-social-facebook-outline"></i></a>&nbsp;</li>
                      <li><a rel="nofollow" href="http://www.youtube.com/GEANTtv" title="YouTube"><i class="icon-lg ion-social-youtube-outline"></i></a>&nbsp;</li>
                    </ul>
                </div>
            </div>
            <br>
            <span class="pull-right text-muted small"><a href="http://www.niif.hu">NIIF Institute</a> ©2015 Mihály Mészáros</span>
        </div>
    </footer>
    <div id="galleryModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg">
        <div class="modal-content">
        	<div class="modal-body">
        		<img src="//placehold.it/1200x700/222?text=..." id="galleryImage" class="img-responsive" />
        		<p>
        		    <br>
        		    <button class="btn btn-primary btn-lg center-block" data-dismiss="modal" aria-hidden="true">Close <i class="ion-android-close"></i></button>
        		</p>
        	</div>
        </div>
        </div>
    </div>
    <div id="aboutModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog">
        <div class="modal-content">
        	<div class="modal-body">
        		<h2 class="text-center">GÉANT4 SA8 STUN/TURN Federation</h2>
        		<h5 class="text-center">
        		    A free federated STUN/TURN service for the Higher Education Research community.
        		</h5>
        		<p class="text-justify">
        		    Lorem ipsum dolor sit amet, ei sed tale appetere, at quo nonumes dissentias. Decore praesent sed et, sit id summo invenire efficiendi. Et mei commodo sententiae, vis an aeterno complectitur, elitr audire pro in. Sit sumo mutat epicuri ea, minim integre his cu. Ne his ridens docendi, ut vis noster audire.
         		</p>
        		<p class="text-center"><a href="https://www.assembla.com/spaces/gn4-webrtc/">More on the project page</a></p>
        		<br>
        		<button class="btn btn-primary btn-lg center-block" data-dismiss="modal" aria-hidden="true"> OK </button>
        	</div>
        </div>
        </div>
    </div>
    <div id="alertModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-sm">
        <div class="modal-content">
        	<div class="modal-body">
        		<h2 class="text-center">Nice Job!</h2>
        		<p class="text-center">You clicked the button, but it doesn't actually go anywhere because this is only a demo.</p>
        		<p class="text-center"><a href="http://www.bootstrapzero.com">Learn more at BootstrapZero</a></p>
        		<br>
        		<button class="btn btn-primary btn-lg center-block" data-dismiss="modal" aria-hidden="true">OK <i class="ion-android-close"></i></button>
        	</div>
        </div>
        </div>
    </div>
    <div id="addServiceModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-md">
        	<div class="modal-content">
        		<div class="modal-body">
        			<h2 class="text-center">Request api_key to a new Service</h2>
        	        	<form class="addservice-form row text-center" id="addservice-form" method="post">
					<div class="col-lg-10 col-lg-offset-1">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="addservice">
						<label>Service URL : </label>
						<input class="form-control" placeholder="Service URL" type="text" name="service_url" id="tokens-service-url">
						<label></label>
						<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">Request Token (api_key) <i class="ion-android-arrow-forward"></i></button>
					</div>
				</form>
	        	</div>
        	</div>
        </div>
    </div>
     <!--scripts loaded here from cdn for performance -->
    <script src="js/jquery_1.9.1.min.js"></script>
    <script src="js/bootstrap_3.3.4.min.js"></script>
    <script src="js/jquery.easing_1.3.min.js"></script>
    <script src="js/wow_1.1.2.js"></script>
    <script src="js/scripts.js"></script>
    <script>
        $(function(){
            $('#contact-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST', //or POST
                    data: $('#contact-form').serialize(),
                    success: function(data){
                          $("#alertModal").modal('show');
                          $('#contact-form-message').val("");
                          
                    }
                });
            });
        });
        $(function(){
            $('#addservice-form').on('submit', function(e){
                e.preventDefault();
		var urls = '/';
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST', //or POST
                    data: $('#addservice-form').serialize(),
                    success: function(data){
			$('#tokens-service-url').val("");
			$('#tokens').load(urls + ' #token_table');
			$('#addServiceModal').modal('toggle');
                    }
                });
            });
        });
    </script>
  </body>
</html>

<?php } ?>
