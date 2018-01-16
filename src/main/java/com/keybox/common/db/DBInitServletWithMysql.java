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
	@SuppressWarnings("unchecked")
	public void init(ServletConfig config) throws ServletException {

		super.init(config);

		MySQLOperatorStr sqlStr= new MySQLOperatorStr();
		
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
			ResultSet rs = statement.executeQuery(sqlStr.getSqlSelectUserTableExist());
			
			if (!rs.next()) {
				resetSSHKey = true;

				
				//create DB objects
				Map maps = new LinkedHashMap<String, String>();    
				maps.put("sqlCreateUserTable", sqlStr.getSqlCreateUserTable());    
		        maps.put("sqlCreateUserThemeTable", sqlStr.getSqlCreateUserThemeTable());    
		        maps.put("sqlCreateSystemTable", sqlStr.getSqlCreateSystemTable());  
		        maps.put("sqlCreateProfilesTable", sqlStr.getSqlCreateProfilesTable());  
		        maps.put("sqlCreateSystemMapTable", sqlStr.getSqlCreateSystemMapTable()); 
		        maps.put("sqlCreateUserMapTable", sqlStr.getSqlCreateUserMapTable()); 
		        maps.put("sqlCreateApplicationKeyTable", sqlStr.getSqlCreateApplicationKeyTable()); 
		        maps.put("sqlCreateStatusTable", sqlStr.getSqlCreateStatusTable());    
		        maps.put("sqlCreateScriptsTable", sqlStr.getSqlCreateScriptsTable()); 
		        maps.put("sqlPublicKeysTable", sqlStr.getSqlCreatePublicKeysTable());    
		        maps.put("sqlSessionLogTable", sqlStr.getSqlCreateSessionLogTable());    
		        maps.put("sqlTerminalLogTable", sqlStr.getSqlCreateTerminalLogTable());    
			       
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
				//String defaultPassword = EncryptionUtil.hash("changeme" + salt);
				String defaultPassword = EncryptionUtil.hash(AppConfig.getProperty("defaultPassword") + salt);
				//File file = new File("/opt/keybox/instance_id");
				File file = new File("/Users/Mac/keybox/instance_id");
				
				if (file.exists()) {
					String str = FileUtils.readFileToString(file, "UTF-8");
					if(StringUtils.isNotEmpty(str)) {
						defaultPassword = EncryptionUtil.hash(str.trim() + salt);
					}
				}
				
				
				//insert default admin user
				PreparedStatement pStmt = connection.prepareStatement(sqlStr.getSqlInsertTerminalLogTable());
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
