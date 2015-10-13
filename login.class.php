<?php
class login{
	//stores database details;
		private $dbServer;
		private $dbUser;
		private $dbPass;
		private $dbName;
		private $dbTable;
		private $userCol; //column name where email or username is stored
		private $pwdCol; //column name where password is stored
		private $saltCol;//column name where salt if any is stored
	//stores login details
		private $user;
		private $password;		
		private $hash; //stores type of hash;
		private $tryCount;
		private $maxTry;
		private $conn;
		
		public $error; //stores error can be accessed through object
		
		private function checkBrute(){
			if($this->tryCount >= $this->maxTry){
				return false;
			}else{
				return true;
			}		
		}
	
		public function __construct(){
			$this->dbServer = $this->dbUser = $this->dbPass = $this->dbName = $this->dbTable = $this->userCol = $this->pwdCol = $this->saltCol = $this->user = $this->password = $this->error = $this->conn = null;
			$this->maxTry = 5; //stores maximum no. of wrong try allowed
			if(isset($_SESSION['login-try'])){
				$this->tryCount = $_SESSION['login-try'];
			}else{
				$this->tryCount=0;
				$_SESSION['login-try'] = $this->tryCount;
			}
			
		}
		//set the database server
		public function setServer($temp){
			$this->dbServer = $temp;
		}
		
		//set the database user
		public function setUser($temp){
			$this->dbUser = $temp;
		}
		
		//set the database user password
		public function setPwd($temp){
			$this->dbPass = $temp;
		}
		
		//set the database name
		public function setdb($temp){
			$this->dbName = $temp;
		}
		
		//set table name
		public function setTable($temp){
			$this->dbTable = $temp;
		}
		public function storeConfig($a,$b,$c,$d,$e){
			$this->dbServer = $a;
			$this->dbUser = $b;
			$this->dbPass = $c;
			$this->dbName = $d;
			$this->dbTable = $e;						
		}
		
		//Create connection to database return false on error
		public function createConn(){
			$this->conn = new mysqli($this->dbServer, $this->dbUser, $this->dbPass, $this->dbName);
			// Check connection
			if ($this->conn->connect_error) {
				$error = $this->conn->connect_error;
			return false;
			}else{
				return true;
			}
		}
		
		//to store column name of username or email field
		public function setEcol($temp){
			$this->userCol = $temp;
		}
		
		//to store column name of password field
		public function setPcol($temp){
			$this->pwdCol = $temp;
		}
		
		//to store column name of salt field if any
		public function setScol($temp){
			$this->saltCol = $temp;
		}
		public function setCols($a,$b){
			$this->userCol = $a;
			$this->pwdCol = $b;
			
		}
		
		//to store password hash type
		public function setHash($temp){
			$this->hash = $temp;
		}
		
		//to check login return true on success and false on failure ans sets $error on failure
		public function authenicate($userName, $password){
			if($this->checkBrute()){
				if($this->saltCol != null){
					$check ="SELECT $this->userCol,$this->pwdCol,$this->saltCol FROM $this->dbTable WHERE $this->userCol = ? ";
					$stmt = $this->conn->stmt_init();
					$stmt->prepare($check);
					$stmt->bind_param("s", $userName);
					$stmt->execute();
					if($stmt->num_rows > 0) {
						$stmt->bind_result($user, $db_password, $salt);
						$row = $stmt->fetch();
						$hashedPassword = hash($this->hash, $password.$salt);
						if($password==$db_password){
							return true;						
						}else{
							$this->error = "Wrong Credentials";
							$_SESSION['login-try'] = $_SESSION['login-try'] + 1;
							return false;
						}										
					}else{
						$this->error = "No such user exists in database";
						$_SESSION['login-try'] = $_SESSION['login-try'] + 1;
						return false;							
					}
					
				}else{					
					$check ="SELECT $userCol,$pwdCol FROM $dbTable WHERE $userCol = ? ";
					$stmt = $conn->stmt_init();
					$stmt->prepare($check);
					$stmt->bind_param("s", $userName);
					$stmt->execute();
					if($stmt->num_rows > 0) {
						$stmt->bind_result($user, $db_password);
						$row = $stmt->fetch();
						$hashedPassword = hash($this->hash,$password);
						if($password==$db_password){
							return true;						
						}else{
							$this->error = "Wrong Credentials";
							$_SESSION['login-try'] = $_SESSION['login-try'] + 1;
							return false;
						}										
					}else{
						$this->error = "No such user exists in database";
						$_SESSION['login-try'] = $_SESSION['login-try'] + 1;
						return false;							
					}
					}
				}else{
					$this->error = "Maximum Number of wrong login attempts exceeded";
					return false;
				}
		}
	
}
