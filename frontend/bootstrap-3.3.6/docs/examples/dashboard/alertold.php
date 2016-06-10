<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="../../favicon.ico">

    <title>Admin Dashboard - Predictive Log Analytics</title>

    <!-- Bootstrap core CSS -->
    <link href="../../dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <link href="../../assets/css/ie10-viewport-bug-workaround.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="dashboard.css" rel="stylesheet">

    <!-- Just for debugging purposes. Don't actually copy these 2 lines! -->
    <!--[if lt IE 9]><script src="../../assets/js/ie8-responsive-file-warning.js"></script><![endif]-->
    <script src="../../assets/js/ie-emulation-modes-warning.js"></script>

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>

    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container-fluid">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">Predictive Log Analytics</a>
        </div>
      </div>
    </nav>

    <div class="container-fluid">
      <div class="row">
        <div class="col-sm-3 col-md-2 sidebar">
          <ul class="nav nav-sidebar">
            <li><b>Archive</b></li>
            <li><a href="#">January 2016</a></li>
            <li><a href="#">March 2016</a></li>
            <li><a href="#">April 2016</a></li>
          </ul>
        </div>
        <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
          <h1 class="page-header">Admin Dashboard</h1>

<!--           <div class="row placeholders">
            <div class="col-xs-6 col-sm-3 placeholder">
              <img src="data:image/gif;base64,R0lGODlhAQABAIAAAHd3dwAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==" width="200" height="200" class="img-responsive" alt="Generic placeholder thumbnail">
              <h4>Label</h4>
              <span class="text-muted">Something else</span>
            </div>
            <div class="col-xs-6 col-sm-3 placeholder">
              <img src="data:image/gif;base64,R0lGODlhAQABAIAAAHd3dwAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==" width="200" height="200" class="img-responsive" alt="Generic placeholder thumbnail">
              <h4>Label</h4>
              <span class="text-muted">Something else</span>
            </div>
            <div class="col-xs-6 col-sm-3 placeholder">
              <img src="data:image/gif;base64,R0lGODlhAQABAIAAAHd3dwAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==" width="200" height="200" class="img-responsive" alt="Generic placeholder thumbnail">
              <h4>Label</h4>
              <span class="text-muted">Something else</span>
            </div>
            <div class="col-xs-6 col-sm-3 placeholder">
              <img src="data:image/gif;base64,R0lGODlhAQABAIAAAHd3dwAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==" width="200" height="200" class="img-responsive" alt="Generic placeholder thumbnail">
              <h4>Label</h4>
              <span class="text-muted">Something else</span>
            </div>
          </div> -->

          <h2 class="sub-header">Threats</h2>
          <div class="table-responsive">
            <?php
              $servername = "10.3.0.164";
              $username = "chase";
              $password = "pla123";
              $dbname = "pla";

              // Create connection
              $conn = new mysqli($servername, $username, $password, $dbname);
              // Check connection
              if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
              } 

              $sql = "SELECT timestamp,threat_type,threat_level,app_name FROM ALERTS;";
              $result = $conn->query($sql);

              if ($result->num_rows > 0) {
                // echo "<table><tr>
                // <th><a href=\"alert.php?sort=time\">Timestamp:</a></th>
                // <th><a href=\"alert.php?sort=type\">Threat Type:</a></th>
                // <th><a href=\"alert.php?sort=level\">Threat Level:</a></th>
                // <th><a href=\"alert.php?sort=name\">App Name:</a></th>
                // </tr>";
                echo "<table><tr><th>Timestamp</th><th>Threat Type</th><th>Threat Level</th><th>App Name</th></tr>";
                // output data of each row
                while($row = $result->fetch_assoc()) {
                	$colour = '';
                	if($row["threat_level"]=='Low'){
                		//$colour = "style='background-color:green'";
                		$colour = "class=\"success\"";
                	} else if ($row["threat_level"]=='High'){
                		//$colour = "style='background-color:red'";
                		$colour = "class=\"danger\"";
                	}else if ($row["threat_level"]=='Medium'){
                		//$colour = "style='background-color:yellow'";
                		$colour = "class=\"warning\"";
                	}
                  echo "<tr $colour>
                  <td>".$row["timestamp"]."</td>
                  <td>".$row["threat_type"]."</td>
                  <td>".$row["threat_level"]."</td>
                  <td>".$row["app_name"]."</td>
                  </tr>";
                }
                echo "</table>";
              } else {
                echo "0 results";
              } 
              $conn->close();
            ?>
             <table class="table table-danger">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Threat Level</th>
                  <th>Threat Type</th>
                  <th>User Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr style="background-color:yellow;">
                  <td>1</td>
                  <td>Apr 29 16:23:30</td>
                  <td>Low</td>
                  <td>DDoS</td>
                  <td>Firefox</td>
                </tr>
                <tr style="background-color:red;">
                  <td>2</td>
                  <td>Apr 29 16:45:30</td>
                  <td>High</td>
                  <td>DDoS</td>
                  <td>Apache Bench</td>
                </tr>
                <tr style="background-color:red;">
                  <td>3</td>
                  <td>Apr 29 16:50:00</td>
                  <td>High</td>
                  <td>DDoS</td>
                  <td>Apache Bench</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script>window.jQuery || document.write('<script src="../../assets/js/vendor/jquery.min.js"><\/script>')</script>
    <script src="../../dist/js/bootstrap.min.js"></script>
    <!-- Just to make our placeholder images work. Don't actually copy the next line! -->
    <script src="../../assets/js/vendor/holder.min.js"></script>
    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <script src="../../assets/js/ie10-viewport-bug-workaround.js"></script>
  </body>
</html>
