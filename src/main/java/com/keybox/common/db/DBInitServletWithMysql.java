/**
 * Copyright 2013 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.keybox.common.db;

import com.keybox.common.util.AppConfig;
import com.keybox.manage.model.Auth;
import com.keybox.manage.util.DBUtils;
import com.keybox.manage.util.EncryptionUtil;
import com.keybox.manage.util.RefreshAuthKeyUtil;
import com.keybox.manage.util.SSHUtil;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry; 
import java.util.Scanner;
 

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Initial startup task.  Creates an SQLite DB and generates
 * the system public/private key pair if none exists
 */

@WebServlet(name = "DBInitServletWithMysql",
		urlPatterns = {"/config"},
		loadOnStartup = 1)		
public class DBInitServletWithMysql extends javax.servlet.http.HttpServlet {

	private static Logger log = LoggerFactory.getLogger(DBInitServletWithMysql.class);

	/**
	 * task init method that created DB and generated public/private keys
	 *
	 * @param config task config
	 * @throws ServletException
	 */
	public void init(ServletConfig config) throws ServletException {

		super.init(config);

		Connection connection = null;
		Statement statement = null;
		//check if reset ssh application key is set
		boolean resetSSHKey = "true".equals(AppConfig.getProperty("resetApplicationSSHKey"));

		log.debug("DBInitServletWithMysql init");
		

		//if DB password is empty generate a random
		if(StringUtils.isEmpty(AppConfig.getProperty("dbPassword"))) {
			String dbPassword = null;
			String dbPasswordConfirm = null;
			if(!"true".equals(System.getProperty("GEN_DB_PASS"))) {
				//prompt for password and confirmation
				while (dbPassword == null || !dbPassword.equals(dbPasswordConfirm)) {
					if (System.console() == null) {
						Scanner in = new Scanner(System.in);
						System.out.println("Please enter database password: ");
						dbPassword = in.nextLine();
						System.out.println("Please confirm database password: ");
						dbPasswordConfirm = in.nextLine();
					} else {
						dbPassword = new String(System.console().readPassword("Please enter database password: "));
						dbPasswordConfirm = new String(System.console().readPassword("Please confirm database password: "));
					}
					if (!dbPassword.equals(dbPasswordConfirm)) {
						System.out.println("Passwords do not match");
					}
				}
			}
			//set password
			if(StringUtils.isNotEmpty(dbPassword)) {
				AppConfig.encryptProperty("dbPassword", dbPassword);
			//if password not set generate a random
			} else {
				System.out.println("Generating random database password");
				AppConfig.encryptProperty("dbPassword", RandomStringUtils.random(32, true, true));
			}
		//else encrypt password if plain-text
		} else if (!AppConfig.isPropertyEncrypted("dbPassword")) {
			AppConfig.encryptProperty("dbPassword", AppConfig.getProperty("dbPassword"));
		}
		
		
//		String dbPassword = AppConfig.getProperty("dbPassword");
//		AppConfig.encryptProperty("dbPassword", AppConfig.getProperty("dbPassword"));
		try {
			connection = DBUtils.getConn();
			statement = connection.createStatement();
			ResultSet rs = statement.executeQuery("select * from information_schema.tables where upper(table_name) = 'USERS' and table_schema='KeyBox'");
			//ResultSet rs = statement.executeQuery("select * from information_schema.tables where upper(table_name) = 'USERS' and table_schema='PUBLIC'");
			if (!rs.next()) {
				resetSSHKey = true;

				String sqlCreateUserTable = String.format(
						"create table if not exists users (\n" + 
						"id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
						", first_nm varchar(100)\n" + 
						", last_nm varchar(100)\n" + 
						", email varchar(200)\n" + 
						", username varchar(100) not null unique\n" + 
						", password varchar(100)\n" + 
						", auth_token varchar(300)\n" + 
						", auth_type varchar(100) not null default '%s'\n" + 
						", user_type varchar(100) not null default 'A'\n" + 
						", salt varchar(100)\n" + 
						", otp_secret varchar(100))"
						,Auth.AUTH_BASIC);
				
				
				String sqlCreateUserThemeTable = "create table if not exists user_theme\n" + 
												"        (user_id INTEGER PRIMARY KEY\n" + 
												"        , bg varchar(7)\n" + 
												"        , fg varchar(7)\n" + 
												"        , d1 varchar(7)\n" + 
												"        , d2 varchar(7)\n" + 
												"        , d3 varchar(7)\n" + 
												"        , d4 varchar(7)\n" + 
												"        , d5 varchar(7)\n" + 
												"        , d6 varchar(7)\n" + 
												"        , d7 varchar(7)\n" + 
												"        , d8 varchar(7)\n" + 
												"        , b1 varchar(7)\n" + 
												"        , b2 varchar(7)\n" + 
												"        , b3 varchar(7)\n" + 
												"        , b4 varchar(7)\n" + 
												"        , b5 varchar(7)\n" + 
												"        , b6 varchar(7)\n" + 
												"        , b7 varchar(7)\n" + 
												"        , b8 varchar(7)\n" + 
												"        , foreign key (user_id) references users(id) on delete cascade);";
				
				
				String sqlCreateSystemTable = "create table if not exists system\n" + 
												"        (id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
												"        , display_nm varchar(100) not null\n" + 
												"        , user varchar(100) not null\n" + 
												"        , host varchar(50) not null\n" + 
												"        , port INTEGER(10) not null\n" + 
												"        , authorized_keys varchar(100) not null\n" + 
												"        , status_cd varchar(100) not null default 'INITIAL');";
				
				String sqlCreateProfilesTable = "create table if not exists `profiles`\n" + 
												"        (id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
												"        , nm varchar(100) not null\n" + 
												"        , `desc` varchar(100) not null);";
				
				String sqlCreateSystemMapTable = "create table if not exists system_map\n" + 
												"        ( profile_id INTEGER\n" + 
												"        , system_id INTEGER\n" + 
												"        , foreign key (profile_id) references profiles(id) on delete cascade\n" + 
												"        , foreign key (system_id) references system(id) on delete cascade\n" + 
												"        , primary key (profile_id, system_id)); ";
				
				String sqlCreateUserMapTable = "create table if not exists user_map\n" + 
												"        ( user_id INTEGER, profile_id INTEGER\n" + 
												"        , foreign key (user_id) references users(id) on delete cascade\n" + 
												"        , foreign key (profile_id) references profiles(id) on delete cascade\n" + 
												"        , primary key (user_id, profile_id));";
				
				String sqlCreateApplicationKeyTable = "create table if not exists application_key\n" + 
														"        (id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
														"        , public_key varchar(500) not null\n" + 
														"        , private_key varchar(2500) not null\n" + 
														"        , passphrase varchar(100));";
				
				
				String sqlCreateStatusTable = "create table if not exists `status`\n" + 
												"   (\n" + 
												"    id INTEGER,\n" + 
												"    user_id INTEGER,\n" + 
												"    status_cd VARCHAR(100) NOT NULL DEFAULT 'INITIAL',\n" + 
												"    FOREIGN KEY (id)\n" + 
												"        REFERENCES system (id)\n" + 
												"        ON DELETE CASCADE,\n" + 
												"    FOREIGN KEY (user_id)\n" + 
												"        REFERENCES users (id)\n" + 
												"        ON DELETE CASCADE,\n" + 
												"    PRIMARY KEY (id , user_id)\n" + 
												"        );";
				
				String sqlCreateScriptsTable = "create table if not exists scripts\n" + 
												"        (id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
												"        , user_id INTEGER\n" + 
												"        , display_nm varchar(100) not null\n" + 
												"        , script varchar(1000) not null\n" + 
												"        , foreign key (user_id) references users(id) on delete cascade);";
				
				String sqlPublicKeysTable = "create table if not exists public_keys\n" + 
											"        (id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
											"        , key_nm varchar(100) not null\n" + 
											"        , type varchar(100)\n" + 
											"        , fingerprint varchar(100)\n" + 
											"        , public_key varchar(200)\n" + 
											"        , enabled boolean not null default true\n" + 
											"        , create_dt timestamp not null default CURRENT_TIMESTAMP()\n" + 
											"        , user_id INTEGER\n" + 
											"        , profile_id INTEGER\n" + 
											"        , foreign key (profile_id) references profiles(id) on delete cascade\n" + 
											"        , foreign key (user_id) references users(id) on delete cascade);";
				
				String sqlSessionLogTable = "create table if not exists session_log\n" + 
											"        (id BIGINT PRIMARY KEY AUTO_INCREMENT\n" + 
											"        , session_tm timestamp default CURRENT_TIMESTAMP\n" + 
											"        , first_nm varchar(50)\n" + 
											"    , last_nm varchar(50)\n" + 
											"        , username varchar(50) not null\n" + 
											"        , ip_address varchar(50));";
				
				String sqlTerminalLogTable = "create table if not exists terminal_log\n" + 
											"        (session_id BIGINT\n" + 
											"        , instance_id INTEGER\n" + 
											"        , output varchar(100) not null\n" + 
											"        , log_tm timestamp default CURRENT_TIMESTAMP\n" + 
											"        , display_nm varchar(100) not null\n" + 
											"        , user varchar(50) not null\n" + 
											"        , host varchar(50) not null\n" + 
											"        , port INTEGER not null\n" + 
											"        , foreign key (session_id) references session_log(id) on delete cascade);";
				
				
				//create DB objects
				 Map maps = new LinkedHashMap();    
			        maps.put("sqlCreateUserTable", sqlCreateUserTable);    
			        maps.put("sqlCreateUserThemeTable", sqlCreateUserThemeTable);    
			        maps.put("sqlCreateSystemTable", sqlCreateSystemTable);  
			        maps.put("sqlCreateProfilesTable", sqlCreateProfilesTable);  
			        maps.put("sqlCreateSystemMapTable", sqlCreateSystemMapTable); 
			        maps.put("sqlCreateUserMapTable", sqlCreateUserMapTable); 
			        maps.put("sqlCreateApplicationKeyTable", sqlCreateApplicationKeyTable); 
			        maps.put("sqlCreateStatusTable", sqlCreateStatusTable);    
			        maps.put("sqlCreateScriptsTable", sqlCreateScriptsTable); 
			        maps.put("sqlPublicKeysTable", sqlPublicKeysTable);    
			        maps.put("sqlSessionLogTable", sqlSessionLogTable);    
			        maps.put("sqlTerminalLogTable", sqlTerminalLogTable);    
			           
			        Iterator it = maps.entrySet().iterator();    
			        while(it.hasNext())    
			        {    
			            Map.Entry entity = (Entry) it.next();    
			            log.debug("[ key =\n" + entity.getKey() +     
			                    ", value =\n " + entity.getValue() + "\n ]");   
			            statement.executeUpdate(entity.getValue().toString());
			            
			        }    
		
				
			
				//if exists readfile to set default password
				String salt = EncryptionUtil.generateSalt();
				String defaultPassword = EncryptionUtil.hash("changeme" + salt);
				//File file = new File("/opt/keybox/instance_id");
				File file = new File("/Users/Mac/keybox/instance_id");
				
				//File file = new File("~/instance_id");
				if (file.exists()) {
					String str = FileUtils.readFileToString(file, "UTF-8");
					if(StringUtils.isNotEmpty(str)) {
						defaultPassword = EncryptionUtil.hash(str.trim() + salt);
					}
				}
				
				String sqlInsertDefaultUser = String.format("insert into users (username, password, user_type, salt) "
						+ "values('%s','%s','%s','%s');"
						,"admin"
						,defaultPassword
						,Auth.MANAGER
						,salt
						);
				
				log.debug("defaultPassword:"+defaultPassword);
				log.debug("sqlInsertDefaultUser:"+sqlInsertDefaultUser);
				
				//insert default admin user
				PreparedStatement pStmt = connection.prepareStatement("insert into users (username, password, user_type, salt) values(?,?,?,?)");
				pStmt.setString(1, "admin");
				pStmt.setString(2, defaultPassword);
				pStmt.setString(3, Auth.MANAGER);
				pStmt.setString(4, salt);
				
				log.debug("Insert Default admin:"+pStmt.toString());
				pStmt.execute();
				DBUtils.closeStmt(pStmt);
				
				
			}
			DBUtils.closeRs(rs);
				
		
		//if reset ssh application key then generate new key
		if (resetSSHKey) {

			//delete old key entry
			String sqlDeleteApplicationKeyTable="delete from application_key";
			PreparedStatement pStmt = connection.prepareStatement(sqlDeleteApplicationKeyTable);
			log.debug("DeleteApplicationKeyTable: "+sqlDeleteApplicationKeyTable);
			pStmt.execute();
			DBUtils.closeStmt(pStmt);

			//generate new key and insert passphrase
			System.out.println("Setting KeyBox SSH public/private key pair");

			//generate application pub/pvt key and get values
			String passphrase = SSHUtil.keyGen();
			String publicKey = SSHUtil.getPublicKey();
			String privateKey = SSHUtil.getPrivateKey();

			//insert new keys
			pStmt = connection.prepareStatement("insert into application_key (public_key, private_key, passphrase) values(?,?,?)");
			pStmt.setString(1, publicKey);
			pStmt.setString(2, EncryptionUtil.encrypt(privateKey));
			pStmt.setString(3, EncryptionUtil.encrypt(passphrase));
			log.debug("InsertApplicationKey: "+pStmt);
			pStmt.execute();
			DBUtils.closeStmt(pStmt);

			System.out.println("KeyBox Generated Global Public Key:");
			System.out.println(publicKey);

			//set config to default
			AppConfig.updateProperty("publicKey", "");
			AppConfig.updateProperty("privateKey", "");
			AppConfig.updateProperty("defaultSSHPassphrase", "${randomPassphrase}");

			//set to false
			AppConfig.updateProperty("resetApplicationSSHKey", "false");

		}

		//delete ssh keys
		SSHUtil.deletePvtGenSSHKey();

	
		} catch (Exception ex) {
			log.error(ex.toString(), ex);
		}
		finally {
			DBUtils.closeStmt(statement);
			DBUtils.closeConn(connection);
		}
		
		RefreshAuthKeyUtil.startRefreshAllSystemsTimerTask();
	}

}
