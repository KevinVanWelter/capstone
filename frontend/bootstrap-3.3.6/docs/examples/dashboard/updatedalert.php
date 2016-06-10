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
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="dashboard.css" rel="stylesheet">
 
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
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li><a href="#">Help</a></li>
          </ul>
		  <!--<form class="navbar-form navbar-right">
            <input type="text" class="form-control" placeholder="Search...">
          </form> -->
        </div>
      </div>
    </nav>

    <div class="container-fluid">
      <div class="row">
        <div class="col-sm-3 col-md-2 sidebar">
          <ul class="nav nav-sidebar">
            <li class="active"><a href="#">Archive<span class="sr-only">(current)</span></a></li>
            <?php
              $servername = "10.3.0.164";
              $username = "chase";
              $password = "pla123";
              $dbname = "pla";

              $conn = new mysqli($servername, $username, $password, $dbname);
              if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
              } 

              // Select the timestamps from the ALERTS table
              $sql = "SELECT timestamp FROM ALERTS ORDER BY TIMESTAMP";
              $result = $conn->query($sql);

              // Create the display table
              if ($result->num_rows > 0) {
                $monthList = array();
                while($row = $result->fetch_assoc()) {
                  $date = date_create_from_format('M j H:i:s', $row["timestamp"]);
                  $month = date_format($date, 'F');
                  if(in_array($month,$monthList)){
                    //echo "Hit";
                  } else {
                    echo "<li><a href=\"#$month\">$month</a></li>";
                    array_push($monthList,$month);
                  }

                }
                //print_r($monthList);

              }
              $conn->close();

            ?>
          </ul>
        </div>
        <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
          <h1 class="page-header">Admin Dashboard</h1>

          <h2 class="sub-header">Threats</h2>
          <div class="table-responsive">
            <?php
              // $servername = "10.3.0.164";
              // $username = "chase";
              // $password = "pla123";
              // $dbname = "pla";

              // Create connection
              $conn = new mysqli($servername, $username, $password, $dbname);
              // Check connection
              if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
              } 
              // Select all rows and columns from the ALERTS table
              $sql = "SELECT timestamp,threat_type,threat_level,app_name FROM ALERTS";


              // if ($_GET['sort'] == 'time')
              // {
              //     $sql .= " ORDER BY timestamp";
              // }
              // elseif ($_GET['sort'] == 'type')
              // {
              //     $sql .= " ORDER BY threat_type";
              // }
              // elseif ($_GET['sort'] == 'level')
              // {
              //     $sql .= " ORDER BY threat_level";
              // }
              // elseif($_GET['sort'] == 'name')
              // {
              //     $sql .= " ORDER BY app_name";
              // }

              $result = $conn->query($sql);

              // Create the display table
              if ($result->num_rows > 0) {

                echo "<table id=\"alertTable\" class=\"table tablesorter\">
                <thead>
                <tr>
                <th>Timestamp</th>
                <th>Threat Type</th>
                <th>Threat Level</th>
                <th>App Name</th>
                </tr>
                </thead>
                <tbody>";

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
                echo "</tbody></table>";
              } else {
                echo "0 results";
              } 

              $conn->close();
            ?>

          </div>
        </div>
      </div>
    </div>

    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <!-- <script>window.jQuery || document.write('<script src="../../assets/js/vendor/jquery.min.js"><\/script>')</script> -->
    <script src="js/bootstrap.min.js"></script>
  </body>
</html>
