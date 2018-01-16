package com.keybox.common.db;

import com.keybox.manage.model.Auth;

public class MySQLOperatorStr {
	
	private String sqlCreateUserTable ;
	private String sqlCreateUserThemeTable ;
	private String sqlCreateSystemTable ;
	private String sqlCreateProfilesTable ;
	private String sqlCreateSystemMapTable ;
	private String sqlCreateUserMapTable ;
	private String sqlCreateApplicationKeyTable ;
	private String sqlCreateStatusTable ;
	private String sqlCreateScriptsTable ;
	private String sqlCreatePublicKeysTable ;
	private String sqlCreateSessionLogTable ;
	private String sqlCreateTerminalLogTable ;
	private String sqlInsertTerminalLogTable ;
	private String sqlSelectUserTableExist ;
	
	

	public String getSqlCreateUserTable() {
		return String.format(
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
	}
	
	public String getSqlCreateUserThemeTable() {
		return "create table if not exists user_theme(\n" + 
				"user_id INTEGER PRIMARY KEY\n" +
				", bg varchar(7)\n" + 
				", fg varchar(7)\n" + 
				", d1 varchar(7)\n" + 
				", d2 varchar(7)\n" + 
				", d3 varchar(7)\n" + 
				", d4 varchar(7)\n" + 
				", d5 varchar(7)\n" + 
				", d6 varchar(7)\n" + 
				", d7 varchar(7)\n" + 
				", d8 varchar(7)\n" + 
				", b1 varchar(7)\n" + 
				", b2 varchar(7)\n" + 
				", b3 varchar(7)\n" + 
				", b4 varchar(7)\n" + 
				", b5 varchar(7)\n" + 
				", b6 varchar(7)\n" + 
				", b7 varchar(7)\n" + 
				", b8 varchar(7)\n" + 
				", foreign key (user_id) references users(id) on delete cascade);";
	}
	
	public String getSqlCreateSystemTable() {
		return "create table if not exists system(\n" + 
				"  id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
				", display_nm varchar(100) not null\n" + 
				", user varchar(100) not null\n" + 
				", host varchar(50) not null\n" + 
				", port INTEGER(10) not null\n" + 
				", authorized_keys varchar(100) not null\n" + 
				", status_cd varchar(100) not null default 'INITIAL');";
	}
	public String getSqlCreateProfilesTable() {
		return  "create table if not exists `profiles`(\n" + 
				" id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
				", nm varchar(100) not null\n" + 
				", `desc` varchar(100) not null);";
	}
	public String getSqlCreateSystemMapTable() {
		return "create table if not exists system_map(\n" + 
				"  profile_id INTEGER\n" + 
				", system_id INTEGER\n" + 
				", foreign key (profile_id) references profiles(id) on delete cascade\n" + 
				", foreign key (system_id) references system(id) on delete cascade\n" + 
				", primary key (profile_id, system_id)); ";
	}
	public String getSqlCreateUserMapTable() {
		return "create table if not exists user_map(\n" + 
				"  user_id INTEGER, profile_id INTEGER\n" + 
				", foreign key (user_id) references users(id) on delete cascade\n" + 
				", foreign key (profile_id) references profiles(id) on delete cascade\n" + 
				", primary key (user_id, profile_id));";
	}
	public String getSqlCreateApplicationKeyTable() {
		return "create table if not exists application_key(\n" + 
				"  id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
				", public_key varchar(500) not null\n" + 
				", private_key varchar(2500) not null\n" + 
				", passphrase varchar(100));";
	}
	public String getSqlCreateStatusTable() {
		return "create table if not exists `status`(\n" + 
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
	}
	public String getSqlCreateScriptsTable() {
		return "create table if not exists scripts(\n" + 
				"  id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
				", user_id INTEGER\n" + 
				", display_nm varchar(100) not null\n" + 
				", script varchar(1000) not null\n" + 
				", foreign key (user_id) references users(id) on delete cascade);";
	}
	public String getSqlCreatePublicKeysTable() {
		return  "create table if not exists public_keys(\n" + 
				"  id INTEGER PRIMARY KEY AUTO_INCREMENT\n" + 
				", key_nm varchar(100) not null\n" + 
				", type varchar(100)\n" + 
				", fingerprint varchar(100)\n" + 
				", public_key varchar(200)\n" + 
				", enabled boolean not null default true\n" + 
				", create_dt timestamp not null default CURRENT_TIMESTAMP()\n" + 
				", user_id INTEGER\n" + 
				", profile_id INTEGER\n" + 
				", foreign key (profile_id) references profiles(id) on delete cascade\n" + 
				", foreign key (user_id) references users(id) on delete cascade);";
	}
	public String getSqlCreateSessionLogTable() {
		return "create table if not exists session_log(\n" + 
				"  id BIGINT PRIMARY KEY AUTO_INCREMENT\n" + 
				", session_tm timestamp default CURRENT_TIMESTAMP\n" + 
				", first_nm varchar(50)\n" + 
				", last_nm varchar(50)\n" + 
				", username varchar(50) not null\n" + 
				", ip_address varchar(50));";
	}
	public String getSqlCreateTerminalLogTable() {
		return "create table if not exists terminal_log(\n" + 
				"  session_id BIGINT\n" + 
				", instance_id INTEGER\n" + 
				", output varchar(100) not null\n" + 
				", log_tm timestamp default CURRENT_TIMESTAMP\n" + 
				", display_nm varchar(100) not null\n" + 
				", user varchar(50) not null\n" + 
				", host varchar(50) not null\n" + 
				", port INTEGER not null\n" + 
				", foreign key (session_id) references session_log(id) on delete cascade);";
	}


	public String getSqlInsertTerminalLogTable() {
		return "insert into users (username, password, user_type, salt) values(?,?,?,?)";
	}
	


	public String getSqlSelectUserTableExist() {
		//table name 	: users
		//db name		: KeyBox
		return "select * from information_schema.tables where upper(table_name) = 'USERS' and table_schema='KeyBox'";
	}
}
