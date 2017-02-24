USE auth;

DROP TABLE auth_table;

CREATE TABLE auth_table (
		id INT NOT NULL AUTO_INCREMENT,
		ip VARCHAR(255) NOT NULL,
		port VARCHAR(10),
		username VARCHAR(255) NOT NULL,
		password VARCHAR(255),
		loc VARCHAR(255),
		PRIMARY KEY (id),
                UNIQUE ip_idx(ip)
		)ENGINE=InnoDB DEFAULT CHARSET=utf8;

