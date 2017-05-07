<?php
use Hackzilla\PasswordGenerator\Generator\ComputerPasswordGenerator;
require_once('vendor/autoload.php');
require_once('Db.php');
if (!isset($_SERVER["AUTH_TYPE"]) || empty($_SERVER["AUTH_TYPE"]) || $_SERVER["AUTH_TYPE"]!="Shibboleth") {
  header("Location: /Shibboleth.sso/Login"); /* Redirect browser */
  exit;
}

// check SAML attributes
$mandatory=array("affiliation","mail","eppn","displayName");
foreach($mandatory as $v) {
    if (isset($_SERVER[$v]) && !empty($_SERVER[$v])){
        $attrib[$v]=$_SERVER[$v];
    } else {
        if($v=="eppn"){
            header("Location: /attribute-error.html"); /* Redirect browser */
            exit();
        } else{
            $attrib[$v]="NULL";
        }
    }
}

$logout_url='https://turn.geant.org/Shibboleth.sso/Logout';

//connectdb
$db_rest = Db::Connection("coturn-rest");
$db_ltc = Db::Connection("coturn-ltc");

// Default realm
const default_realm='turn.geant.org';

//create csfr token
$a = session_id();
if(empty($a))session_start();
if (empty($_SESSION['token'])) {
    if (function_exists('mcrypt_create_iv')) {
        $_SESSION['token'] = bin2hex(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
    } else {
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}
$token = $_SESSION['token'];

function mkpasswd($length) {
    $generator = new ComputerPasswordGenerator();
    
    $generator
      ->setUppercase()
      ->setLowercase()
      ->setNumbers()
      ->setSymbols(false)
      ->setLength($length);
    
    $password = $generator->generatePasswords();
    return $password[0];
 
};

function huston_we_have_a_problem($problem){
    http_response_code(500);
    echo $problem;
}
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
                    
                    $mail->setFrom('stun-devops@listserv.niif.hu', 'Contact Webform');
                    // set recipient
                    $mail->addAddress('stun-devops@listserv.niif.hu', 'Voice Video Collaboration');     // Add a recipient
                    
                    $mail->isHTML(true);                                  // Set email format to HTML
                    
                    $mail->Subject = 'Contact Form from '.default_realm;
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
                case "adduser":
        	    $query="INSERT INTO turnusers_lt (eppn,email,displayname,name,realm,hmackey) values(:eppn,:mail,:displayname,:username,:realm,:HA1)";
                    $sth = $db_ltc->prepare($query);
                    $sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attrib["mail"], PDO::PARAM_STR);
                    $sth->bindValue(':displayname', $attrib["displayName"], PDO::PARAM_STR);
                    $sth->bindValue(':username', $_POST['username'], PDO::PARAM_STR);
                    $sth->bindValue(':realm', $_POST['realm'], PDO::PARAM_STR);
                    $sth->bindValue(':HA1', md5($_POST['username'].':'.$_POST['realm'].':'.$_POST['password']), PDO::PARAM_STR);
                    if($sth->execute()){
        		//success
        	    } else {
        		huston_we_have_a_problem('New user could not be inserted.');
        	    }
                    break;
                case "updateuser":
        	    $query="UPDATE turnusers_lt SET hmackey=:HA1,email=:mail,displayname=:displayname,name=:username,realm=:realm WHERE eppn=:eppn AND id=:id and realm='default_realm'";
                    $sth = $db_ltc->prepare($query);
                    $sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attrib["mail"], PDO::PARAM_STR);
                    $sth->bindValue(':displayname', $attrib["displayName"], PDO::PARAM_STR);
                    $sth->bindValue(':username', $_POST['username'], PDO::PARAM_STR);
                    $sth->bindValue(':realm', $_POST['realm'], PDO::PARAM_STR);
                    $sth->bindValue(':HA1', md5($_POST['username'].':'.$_POST['realm'].':'.$_POST['password']), PDO::PARAM_STR);
                    $sth->bindValue(':id', $_POST['row_id'], PDO::PARAM_STR);
                    if($sth->execute()){
        		//success
        	    } else {
        		huston_we_have_a_problem('New user could not be updated.');
        	    }
                    break;
                 case "addservice":
                    $token = mkpasswd(32);
        	    
        	    $query="INSERT INTO token (eppn,email,displayname,token,service_url,realm) values(:eppn,:mail,:displayname,:token,:service_url,:realm)";
                    $sth = $db_rest->prepare($query);
                    $sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attrib["mail"], PDO::PARAM_STR);
                    $sth->bindValue(':displayname', $attrib["displayName"], PDO::PARAM_STR);
                    $sth->bindValue(':token', $token, PDO::PARAM_STR);
                    $sth->bindValue(':service_url', $_POST['service_url'], PDO::PARAM_STR);
                    $sth->bindValue(':realm', $_POST['realm'], PDO::PARAM_STR);
                    if($sth->execute()){
        		//success
        	    } else {
        		huston_we_have_a_problem('New token could not be inserted.');
        	    }
                    break;
                 case "updateservice":
                    $token = mkpasswd(32);
        	    
        	    $query="UPDATE token set created=NOW(),email=:mail,displayname=:displayname,token=:token,service_url=:service_url,realm=:realm WHERE eppn=:eppn AND id=:id and realm='default_realm'";
                    $sth = $db_rest->prepare($query);
                    $sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attrib["mail"], PDO::PARAM_STR);
                    $sth->bindValue(':displayname', $attrib["displayName"], PDO::PARAM_STR);
                    $sth->bindValue(':token', $token, PDO::PARAM_STR);
                    $sth->bindValue(':service_url', $_POST['service_url'], PDO::PARAM_STR);
                    $sth->bindValue(':realm', $_POST['realm'], PDO::PARAM_STR);
                    $sth->bindValue(':id', $_POST['row_id'], PDO::PARAM_STR);
                    if($sth->execute()){
        		//success
        	    } else {
        		huston_we_have_a_problem('New token could not be updated.');
        	    }
                    break;
                 case "del":
                    $table="";
                    switch ($_POST["table"]) {
                        case "turnusers_lt":
                            $table="turnusers_lt";
                            $db=$db_ltc;
                            break;
                        case "token":
                            $table="token";
                            $db=$db_rest;
                            break;
                        default:
        		huston_we_have_a_problem('Invalid table parameter received!');
                    }

        	    $query="DELETE from ".$table." where eppn=:eppn and email=:mail and id=:id";
                    $sth = $db->prepare($query);
                    $sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
                    $sth->bindValue(':mail', $attrib["mail"], PDO::PARAM_STR);
                    $sth->bindValue(':id', $_POST['row_id'], PDO::PARAM_STR);
                    if($sth->execute()){
                        echo $table;
        		//success
        	    } else {
        		huston_we_have_a_problem('Cannot delete from '.$table.'table row id:'.$_POST['id'].' !');
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
                <a class="navbar-brand page-scroll" href="https://wiki.geant.org/display/WRTC/GN4-1+WebRTC+Roadmap"><i class="ion-ios-flask-outline"></i> GN4 WebRTC Lab</a>
            </div>
            <div class="navbar-collapse collapse" id="bs-navbar">
                <ul class="nav navbar-nav">
                    <li>
                        <a class="page-scroll" href="#intro">Intro</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#ltc">Password</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#ltc-map">Password Servers</a>
                    </li>
                     <li>
                        <a class="page-scroll" href="#rest">REST API</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#rest-map">REST Servers</a>
                    </li>
                     <li>
                        <a class="page-scroll" href="#oauth">Oauth</a>
                    </li>
                    <li>
                        <a class="page-scroll" href="#last">Contact</a>
                    </li>
                    <li>
                        <a href="<?php echo $logout_url; ?>">Logout</a>
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
                <a href="#video-background" id="toggleVideo" data-toggle="collapse" class="btn btn-primary btn-xl">Toggle Video</a> &nbsp; <a href="#intro" class="btn btn-primary btn-xl page-scroll">Get Started</a>
            </div>
        </div>
        <video style="visibility: visible; animation-delay: 0.5s; animation-name: fadeIn;" autoplay="autoplay" loop="" class="fillWidth fadeIn wow collapse in" data-wow-delay="0.5s" poster="img/bg.jpg" id="video-background">
            <source src="/video/bg.mp4" type="video/mp4">Your browser does not support the video tag. I suggest you upgrade your browser.
        </video>
    </header>
    <section class="bg-primary" id="intro">
        <div class="container">
            <div class="row">
                <div class="col-lg-6 col-lg-offset-3 col-md-8 col-md-offset-2 text-center">
                    <h2 class="margin-top-0 text-primary">Welcome to STUN/TURN pilot</h2>
                    <br>
                    <p class="text-faded">
With the IPv4 address exhaustion, and because of many security and other concerns the Internet users will connect more and more to the Internet through NAT and Packet Filters/Firewalls. Actually almost all service provider (e.g. mobile internet, homes) are using NAT. These environments makes hard or impossible the direct Real Time Communication (RTC) and this way we need a Standard based protocol called ICE that solves this traveral issue. ICE depends on STUN/TURN infrastructure.<br>The goal is in this pilot to demonstrate that a Europe wide STUN/TURN service could be build up from Open Source components to serve ICE agents, and RTC services like WebRTC and all in all our community.
                    </p>
                    <a href="#features" class="btn btn-default btn-xl page-scroll">Learn More</a>
                </div>
            </div>
        </div>
    </section>
    <section id="ltc">
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">Password</h2>
                    <h3>Long Term Credential Mechanism</h3>
                    <hr class="primary">
		    <br>
                    <h3>STUN/TURN Server:<h3>
                    <h3 data-wow-delay="0.5s" class="wow rubberBand text-primary">ltc.<?php echo default_realm; ?></h3>
		    <br>
                </div>
            </div>
        </div>
        <div class="container" id="passwords">
            <div class="row col-md-8 col-md-offset-2 custyle" id="password_table">
<?php       
$query="SELECT * FROM turnusers_lt where eppn=:eppn and realm='".default_realm."'";
$sth = $db_ltc->prepare($query);
$sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);
if (empty($result)){
    echo '            <a href="#addUserModal" data-toggle="modal" data-target="#addUserModal" class="btn btn-primary btn-xs pull-right" id="addUserButton"><b>+</b> Add new User</a>'; 
}
?>
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
foreach ($result as $row => $columns) {
echo"                    <tr>
                        <td>".$columns["name"]."</td>
                        <td>".$columns["realm"]."</td>
                        <td>".$columns["hmackey"]."</td>
                        <td class=\"text-center\">
                            <a href=\"#renewUserModal\" data-toggle=\"modal\" data-target=\"#renewUserModal\" data-id=\"".$columns['id']."\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-refresh\"></span> Renew</a>
                            <a href=\"#delModal\" data-toggle=\"modal\" data-target=\"#delModal\" data-id=\"".$columns['id']."\" data-table=\"turnusers_lt\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-delete\"></span> Del</a>
                        </td>
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
    <section class="bg-dark" id="ltc-map">
<?php
$query="select fqdn,organization,ip,latitude,longitude from server left join ip on ip.server_id=server.id order by latitude,longitude,server.id,ip.ipv6";
$sth = $db_ltc->prepare($query);
if($sth->execute()){
  //success
 $result = $sth->fetchAll(PDO::FETCH_ASSOC);
 $lat=0;
 $lng=0;
 $TURNservers=array();
 foreach ($result as $row => $columns) {
   if ( $lat == $columns["latitude"] && $lng == $columns["longitude"]) {
     end($TURNservers);
     $TURNservers[key($TURNservers)]['content'] .= "FQDN: ".$columns["fqdn"]." - IP: ".$columns["ip"]."<br>";
   } else {   
     $lng=$columns["longitude"];
     $lat=$columns["latitude"];
     $TURNserver= array(
       "position" => array ("lat" => (float)$lat, "lng" => (float)$lng), 
       "title" => $columns["organization"], 
       "content" => "FQDN: ".$columns["fqdn"]." - IP: ".$columns["ip"]."<br>"
     );
     $TURNservers[] = $TURNserver;
   }  
 }
 if (empty($result)){
   print("DB error: empty result!");
 }
} else {
   print("DB error: conncetion error!");
};

?>
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">LTC Servers on Maps</h2>
                    <hr class="primary">
                </div>
            </div>

                    <div id="ltc-map-api" style="height: 600px ; width:100%;"></div>
                    <script>
                
                      function initMapREST() {
                        var TURNservers = <?php echo json_encode($TURNservers);?>;
                       
                        var myLatLng = {lat: 51.72702830741035, lng: 8.898925500000018};
                
                        var mapltc = new google.maps.Map(document.getElementById('ltc-map-api'), {
                          zoom: 3,
                          center: myLatLng,
                          styles: [{"featureType":"administrative","elementType":"all","stylers":[{"saturation":"-100"}]},{"featureType":"administrative.province","elementType":"all","stylers":[{"visibility":"off"}]},{"featureType":"landscape","elementType":"all","stylers":[{"saturation":-100},{"lightness":65},{"visibility":"on"}]},{"featureType":"poi","elementType":"all","stylers":[{"saturation":-100},{"lightness":"50"},{"visibility":"simplified"}]},{"featureType":"road","elementType":"all","stylers":[{"saturation":"-100"}]},{"featureType":"road.highway","elementType":"all","stylers":[{"visibility":"simplified"}]},{"featureType":"road.arterial","elementType":"all","stylers":[{"lightness":"30"}]},{"featureType":"road.local","elementType":"all","stylers":[{"lightness":"40"}]},{"featureType":"transit","elementType":"all","stylers":[{"saturation":-100},{"visibility":"simplified"}]},{"featureType":"water","elementType":"geometry","stylers":[{"hue":"#ffff00"},{"lightness":-25},{"saturation":-97}]},{"featureType":"water","elementType":"labels","stylers":[{"lightness":-25},{"saturation":-100}]}]
                        });
                
                        function draw() {
                          for (var i = 0; i < TURNservers.length; i++) {
                            addMarkerWithTimeout(TURNservers[i], i * 200);
                          }
                        }
                
                        function addMarkerWithTimeout(TURNserver, timeout) {
                          window.setTimeout(function() {
                            var marker = new google.maps.Marker({
                              position: TURNserver.position,
                              map: mapltc,
                              title: TURNserver.title,
                              animation: google.maps.Animation.DROP
                            });
                            marker.addListener('click', function() {
                              var infowindow = new google.maps.InfoWindow({
                                content: TURNserver.content
                              });
                              infowindow.open(mapltc, marker);
                              
                            });
                          }, timeout);
                        }
                        draw();
                      }
                      </script>
       </div>
        
    </section>
    <section class="bg-dark" id="rest">
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
                <a href="https://api.<?php echo default_realm ;?>" target="ext" class="btn btn-default btn-lg wow pulse">The REST API Documentation</a>
            </div>
        </div>
        <hr/>
        <div class="container text-center">
              <div class="call-to-action">
                <a href="/rest-sample.html" target="ext" class="btn btn-default btn-lg wow bounceInLeft">Sample PHP code</a>
            </div>
        </div>
        <hr/>
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
$query="SELECT id,token,service_url,realm,(created + INTERVAL 1 YEAR) as expire FROM token where eppn=:eppn and realm='".default_realm."'";
$sth = $db_rest->prepare($query);
$sth->bindValue(':eppn', $attrib["eppn"], PDO::PARAM_STR);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);
foreach ($result as $row => $columns) {
echo"                    <tr>
                        <td>".$columns["token"]."</td>
                        <td>".$columns["service_url"]."</td>
                        <td>".$columns["realm"]."</td>
                        <td>".$columns["expire"]."</td>
                        <td class=\"text-center\">
                            <a href=\"#renewServiceModal\" data-toggle=\"modal\" data-target=\"#renewServiceModal\" data-id=\"".$columns['id']."\" data-service_url=\"".$columns['service_url']."\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-refresh\"></span> Renew</a>
                            <a href=\"#delModal\" data-toggle=\"modal\" data-target=\"#delModal\" data-id=\"".$columns['id']."\" data-table=\"token\" class=\"btn btn-primary btn-xs\"><span class=\"ion-android-delete\"></span> Del</a>
                       </td>
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
                        <p class="text-muted">Protection against attacks</p>
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
    <section class="bg-dark" id="rest-map">
<?php
$query="select fqdn,organization,ip,latitude,longitude from server left join ip on ip.server_id=server.id order by latitude,longitude,server.id,ip.ipv6";
$sth = $db_rest->prepare($query);
if($sth->execute()){
  //success
 $result = $sth->fetchAll(PDO::FETCH_ASSOC);
 $lat=0;
 $lng=0;
 $TURNservers=array();
 foreach ($result as $row => $columns) {
   if ( $lat == $columns["latitude"] && $lng == $columns["longitude"]) {
     end($TURNservers);
     $TURNservers[key($TURNservers)]['content'] .= "FQDN: ".$columns["fqdn"]." - IP: ".$columns["ip"]."<br>";
   } else {   
     $lng=$columns["longitude"];
     $lat=$columns["latitude"];
     $TURNserver= array( 
       "position" => array ("lat" => (float)$lat, "lng" => (float)$lng), 
       "title" => $columns["organization"], 
       "content" => "FQDN: ".$columns["fqdn"]." - IP: ".$columns["ip"]."<br>"
     );
     $TURNservers[] = $TURNserver;
   }  
 }
 if (empty($result)){
   print("DB error: empty result!");
 }
} else {
   print("DB error: conncetion error!");
};

?>
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">REST API Servers on Maps</h2>
                    <hr class="primary">
                </div>
            </div>

                    <div id="rest-map-api" style="height: 600px ; width:100%;"></div>
                    <script>
                
                      function initMapLTC() {
                        var TURNservers = <?php echo json_encode($TURNservers);?>;
                       
                        var myLatLng = {lat: 51.72702830741035, lng: 8.898925500000018};
                
                        var maprest = new google.maps.Map(document.getElementById('rest-map-api'), {
                          zoom: 3,
                          center: myLatLng,
                          styles: [{"featureType":"administrative","elementType":"all","stylers":[{"saturation":"-100"}]},{"featureType":"administrative.province","elementType":"all","stylers":[{"visibility":"off"}]},{"featureType":"landscape","elementType":"all","stylers":[{"saturation":-100},{"lightness":65},{"visibility":"on"}]},{"featureType":"poi","elementType":"all","stylers":[{"saturation":-100},{"lightness":"50"},{"visibility":"simplified"}]},{"featureType":"road","elementType":"all","stylers":[{"saturation":"-100"}]},{"featureType":"road.highway","elementType":"all","stylers":[{"visibility":"simplified"}]},{"featureType":"road.arterial","elementType":"all","stylers":[{"lightness":"30"}]},{"featureType":"road.local","elementType":"all","stylers":[{"lightness":"40"}]},{"featureType":"transit","elementType":"all","stylers":[{"saturation":-100},{"visibility":"simplified"}]},{"featureType":"water","elementType":"geometry","stylers":[{"hue":"#ffff00"},{"lightness":-25},{"saturation":-97}]},{"featureType":"water","elementType":"labels","stylers":[{"lightness":-25},{"saturation":-100}]}]
                        });
                
                        function draw() {
                          for (var i = 0; i < TURNservers.length; i++) {
                            addMarkerWithTimeout(TURNservers[i], i * 200);
                          }
                        }
                
                        function addMarkerWithTimeout(TURNserver, timeout) {
                          window.setTimeout(function() {
                            var marker = new google.maps.Marker({
                              position: TURNserver.position,
                              map: maprest,
                              title: TURNserver.title,
                              animation: google.maps.Animation.DROP
                            });
                            marker.addListener('click', function() {
                              var infowindow = new google.maps.InfoWindow({
                                content: TURNserver.content
                              });
                              infowindow.open(maprest, marker);
                              
                            });
                          }, timeout);
                        }
                        draw();
                      }
                      </script>
       </div>
        
    </section>
     <section id="oauth">
        <div class="container">
            <div class="row">
                <div class="col-lg-12 text-center">
                    <h2 class="margin-top-0 text-primary">OAUTH</h2>
                    <h3>Third Party Authorization Mechanism</h3>
                    <hr class="primary">
                    <h1>It is in the pipe<hr> comming soon...</h1>
                </div>
                <div class="col-lg-8 col-lg-offset-2 text-center">
                    <p class="text-muted">Our project target is to support all available STUN/TURN authentication/authorization mechanism.<br>
Unfortunately currently no OAUTH client implementation exists yet, but latter the service could be easily extended to support that when clients implementation will appear.</p>
                </div>
            </div>
        </div>
    </section>
    <section class="container-fluid bg-primary" id="features">
        <div class="row">
            <div class="col-xs-10 col-xs-offset-1 col-sm-6 col-sm-offset-3 col-md-4 col-md-offset-4">
                <h2 class="text-center text-primary">Features</h2>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>Traversal</h3>
                    <div class="media-body media-middle">
                        <p>The STUN/TURN service makes available traversal through packet fileters and NATs</p>
                    </div>
                    <div class="media-right">
                        <i class="icon-lg ion-ios-bolt-outline"></i>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeIn">
                    <h3>IPv6 Ready!</h3>
                    <div class="media-left">
                        <a href="https://www.ripe.net/publications/ipv6-info-centre"><i class="icon-lg ion-ios-cloud-download-outline"></i></a>
                    </div>
                    <div class="media-body media-middle">
                        <p>Makes available a smooth transition to the next generation Internet Protocol, IPv6.</p>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>WebRTC</h3>
                    <div class="media-body media-middle">
                        <p>Ready to serve WebRTC services.<br>Supports multiple auth mechansims.</p>
                    </div>
                    <div class="media-right">
                        <i class="icon-lg ion-ios-videocam-outline"></i>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeIn">
                    <h3>Open</h3>
                    <div class="media-left">
                        <i class="icon-lg ion-ios-heart-outline"></i>
                    </div>
                    <div class="media-body media-middle">
                        <p>All SW components are Open Source.<br>Transparent! Operated by multiple NRENs.</p>
                    </div>
                </div>
                <hr>
                <div style="visibility: hidden; animation-name: none;" class="media wow fadeInRight">
                    <h3>Reliable</h3>
                    <div class="media-body media-middle">
                        <p>It is distributed around European continent.<br>If possible use the closest server.</p>
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
    <section id="background" class="bg-primary">
        <div class="container">
            <div class="row">
                <div class="col-lg-8 col-lg-offset-2 text-center">
                    <h2 style="visibility: hidden; animation-name: none;" class="text-primary margin-top-0 wow fadeIn">How it works?</h2>
                    <hr class="primary">
	            <br>
	            <br>
	            <br>
                </div>
            </div>
        </div>
        <div class="container-fluid no-padding">
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
                            <input class="form-control" placeholder="Name" type="text" name="Name" value="<?php echo $attrib['displayName'];?>">
                        </div>
                        <div class="col-md-4">
                            <label></label>
                            <input class="form-control" placeholder="Email" type="text" name="Email" value="<?php echo $attrib['mail'];?>">
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
                        <li><a href="https://wiki.geant.org/display/Multimedia/SIG-Multimedia+Home">SIG-MM</a></li>
                        <li><a href="https://wiki.geant.org/display/WRTC/GN4-1+WebRTC+Roadmap">Roadmap</a></li>
                        <li><a href="https://wiki.geant.org/display/WRTC/TF-WebRTC+Task+Force+on+WebRTC">TF-WebRTC</a></li>
                        <li><a href="https://wiki.geant.org/download/attachments/56918574/GN4-1%20SA8T2%20Tech%20Scout%20-%20STUN_TURN_ICE%20-%20v1.0-final.pdf?version=1&modificationDate=1461935196846&api=v2">TURN Tech Scout</a></li>
                     </ul>
                </div>
                <div class="col-xs-6 col-sm-3 column">
                    <h4>About</h4>
                    <ul class="list-unstyled">
                        <li><a href="mailto:stun-devops@listserv.niif.hu">Contact Us</a></li>
                        <li><a href="mailto:stun-devops@listserv.niif.hu?subject=Technical Support">Support</a></li>
                        <li><a href="privacy.html">Privacy Policy</a></li>
                        <li><a href="terms.html">Terms &amp; Conditions</a></li>
                    </ul>
                </div>
                <div class="col-xs-12 col-sm-3 column">
                    <h4>Stay Posted</h4>
                    <form action="https://lists.geant.org/sympa">
                        <div class="form-group">
                          <input type="hidden" name="list" value="webrtc" />
                          <input type="hidden" name="action" value="subrequest" />
                          <input class="form-control" title="No spam, we promise!" name="email" placeholder="Tell us your email" type="text">
                        </div>
                        <div class="form-group">
                          <button class="btn btn-primary" type="submit">Subscribe for updates</button>
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
            <span class="pull-right text-muted small"><a href="http://www.niif.hu/en">NIIF Institute</a> ©2015 Mihály Mészáros</span>
        </div>
    </footer>
    <div id="galleryModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg">
        <div class="modal-content">
        	<div class="modal-body">
        		<img src="" id="galleryImage" class="img-responsive" />
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
        		<h2 class="text-center">GÉANT4 Federated STUN/TURN Pilot Service</h2>
        		<h5 class="text-center">
        		    This is a free federated STUN/TURN pilot service for the Higher Education Research community.
        		</h5>
        		<p class="text-justify">
There could be plenty of barriers that may prevent Peer to Peer (P2P) direct communication: e.g. Firewalls/Packet Filters, NATs, Multiple Interfaces (Cable/VPN/WIFI/Mobile Internet), Next Gent IP transition (Multiple IP protocols IPv4,IPv6), etc. The goal is in this pilot to demonstrate that a Europe wide service could be build up from Open Source components that could serve our community Intercalative Connectivity Establishment (ICE) Agents. Which base on STUN/TURN servers. ICE is an IETF standard, that makes possible Real Time Communication (RTC) through NAT and Firewalls and also help in IPv6 smooth transition. It is widely deployed and used.  For example we could find it in VoIP phone, Telepresence/VideoConference systems,  and in ALL WebRTC clients like all Web browsers.
         		</p>
        		<p class="text-center"><a href="#last" onclick="$('#aboutModal').modal('hide');">In case of any question please don't hesitate to contact us.</a></p>
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
        		<h2 class="text-center">Many thanks for your feedback!</h2>
        		<p class="text-center">We will get back to you soon!</p>
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
        	        	<form class="addservice-form form" id="addservice-form" method="post">
					<div class="form-group">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="addservice">
						<label class="control-label">Service URL</label>
						<input class="form-control" placeholder="Service URL" type="text" name="service_url" id="tokens-service-url">
                                        </div>
					<div class="form-group">
						<label class="control-label">Realm</label>
						<input class="form-control" type="text" name="realm" value="<?php echo default_realm; ?>" readonly>
					</div>
					<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">Request Token (api_key) <i class="ion-android-arrow-forward"></i></button>
				</form>
	        	</div>
        	</div>
        </div>
    </div>
    <div id="renewServiceModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-md">
        	<div class="modal-content">
        		<div class="modal-body">
        			<h2 class="text-center">Request api_key to a new Service</h2>
        	        	<form class="renewservice-form form" id="renewservice-form" method="post">
					<div class="form-group">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="updateservice">
						<input type="hidden" name="row_id" class="row_id">
						<label class="control-label">Service URL</label>
						<input class="form-control service_url" placeholder="Service URL" type="text" name="service_url">
                                        </div>
					<div class="form-group">
						<label class="control-label">Realm</label>
						<input class="form-control" type="text" name="realm" value="<?php echo default_realm; ?>" readonly>
					</div>
					<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">Renew Token (api_key) <i class="ion-android-arrow-forward"></i></button>
				</form>
	        	</div>
        	</div>
        </div>
    </div>
    <div id="renewUserModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-md">
        	<div class="modal-content">
        		<div class="modal-body">
        			<h2 class="text-center">Please keep and notice!</h2>
                                <h3 class="text-center">This is your new Username Password and Realm!</h2>
                                <hr/>
        	        	<form role="form" class="form-horizontal renewuser-form" id="renewuser-form" method="post">
					<div class="form-group">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="updateuser">
						<input type="hidden" name="row_id" class="row_id">
						<label class="control-label col-sm-2">Username</label>
                                                <div class="col-sm-10">
						    <input class="form-control " type="text" name="username" value="<?php echo str_replace("@","_at_",$attrib["mail"]); ?>" readonly>
                                                </div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2">Password</label>
                                                <div class="col-sm-10">
						<input class="form-control" type="text" name="password" value="<?php echo mkpasswd(32); ?>" readonly>
                                                </div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2">Realm</label>
                                                <div class="col-sm-10">
						<input class="form-control" type="text" name="realm" value="<?php echo default_realm; ?>" readonly>
                                                </div>
                                                <br>
					</div>
					<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">Renew Password Credential <i class="ion-android-arrow-forward"></i></button>
				</form>
	        	</div>
        	</div>
        </div>
    </div>
    <div id="addUserModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-md">
        	<div class="modal-content">
        		<div class="modal-body">
        			<h2 class="text-center">Please keep and notice!</h2>
                                <h3 class="text-center">This is your new Username Password and Realm!</h2>
                                <hr/>
        	        	<form role="form" class="form-horizontal adduser-form" id="adduser-form" method="post">
					<div class="form-group">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="adduser">
						<label class="control-label col-sm-2">Username</label>
                                                <div class="col-sm-10">
						    <input class="form-control " type="text" name="username" value="<?php echo str_replace("@","_at_",$attrib["mail"]); ?>" readonly>
                                                </div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2">Password</label>
                                                <div class="col-sm-10">
						<input class="form-control" type="text" name="password" value="<?php echo mkpasswd(32); ?>" readonly>
                                                </div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2">Realm</label>
                                                <div class="col-sm-10">
						<input class="form-control" type="text" name="realm" value="<?php echo default_realm; ?>" readonly>
                                                </div>
                                                <br>
					</div>
					<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">Request Password Credential <i class="ion-android-arrow-forward"></i></button>
				</form>
	        	</div>
        	</div>
        </div>
    </div>
   <div id="delModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-sm">
        <div class="modal-content">
        	<div class="modal-body">
        		<h2 class="text-center">Are You sure ?!</h2>
        		<p class="text-center">You clicked on the delete button. This is your last chance to cancel...</p>
        	        	<form class="del-form row text-center" id="del-form" method="post">
					<div class="col-lg-10 col-lg-offset-1">
                                                <input type="hidden" name="token" value="<?php echo $token; ?>" />
						<input type="hidden" name="form" value="del">
						<input type="hidden" name="row_id" class="row_id">
						<input type="hidden" name="table" id="table">
						<label></label>
						<button type="submit" class="btn btn-primary btn-lg center-block" aria-hidden="true">I am  Sure <i class="ion-android-arrow-forward"></i></button>
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
            $('#del-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
                    data: $('#del-form').serialize(),
                    success: function(data){
                          switch(data) {
                              case 'turnusers_lt':
			          $('#passwords').load('/ #password_table');
                                  break;
                              case 'token':
			          $('#tokens').load('/ #token_table');
                                  break;
                          }
                          $("#delModal").modal('toggle');
                    }
                });
            });
        });
        $(function(){
            $('#contact-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
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
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
                    data: $('#addservice-form').serialize(),
                    success: function(data){
			$('#tokens-service-url').val("");
			$('#tokens').load('/ #token_table');
			$('#addServiceModal').modal('toggle');
                    }
                });
            });
        });
        $(function(){
            $('#renewuser-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
                    data: $('#renewuser-form').serialize(),
                    success: function(data){
			$('#passwords').load('/ #password_table');
			$('#renewUserModal').modal('toggle');
                    }
                });
            });
        });
        $(function(){
            $('#renewservice-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
                    data: $('#renewservice-form').serialize(),
                    success: function(data){
			$('#tokens').load('/ #token_table');
			$('#renewServiceModal').modal('toggle');
                    }
                });
            });
        });
        $(function(){
            $('#adduser-form').on('submit', function(e){
                e.preventDefault();
                $.ajax({
                    url: '/', //this is the submit URL
                    type: 'POST',
                    data: $('#adduser-form').serialize(),
                    success: function(data){
			$('#passwords').load('/ #password_table');
			$('#addUserModal').modal('toggle');
                    }
                });
            });
        });
        $(document).on('click','a[data-toggle=modal], button[data-toggle=modal]', function () {
            // id
            var data_id = '';
            if (typeof $(this).data('id') !== 'undefined') {
              data_id = $(this).data('id');
            }
            $('.row_id').val(data_id);
            // table
            var data_table = '';
            if (typeof $(this).data('table') !== 'undefined') {
              data_table = $(this).data('table');
            }
            $('#table').val(data_table);
            var service_url = '';
            if (typeof $(this).data('service_url') !== 'undefined') {
              service_url = $(this).data('service_url');
            }
            $('.service_url').val(service_url);
          });
    </script>
    <script>
    function initMap() {
      initMapLTC();
      initMapREST();
    }
    </script>
    <script async defer
        src="https://maps.googleapis.com/maps/api/js?key=AIzaSyBdl6wVohcvpT5Q9hrIB4Uo8qVqKiwratg&callback=initMap">
    </script>
 
  </body>
</html>

<?php } ?>
