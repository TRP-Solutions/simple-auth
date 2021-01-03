--
-- SimpleAuth is licensed under the Apache License 2.0 license
-- https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
--

--
-- Database
--

CREATE DATABASE IF NOT EXISTS `simpleauth`;
USE `simpleauth`;

--
-- Tables
--

CREATE TABLE IF NOT EXISTS `auth_access` (
	`user_id` int(10) unsigned NOT NULL,
	`permission` varchar(30) NOT NULL,
	PRIMARY KEY (`user_id`,`permission`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `auth_token` (
	`user_id` int(10) unsigned NOT NULL,
	`token` varchar(44) NOT NULL,
	`expires` DATETIME NOT NULL,
	PRIMARY KEY (`token`),
	KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `auth_user` (
	`id` int(10) unsigned NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`password` varchar(255) NOT NULL,
	`confirmation` varchar(255) NOT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Data
--

INSERT INTO `auth_user` (`id`, `username`, `password`) VALUES
(1, 'johndoe', '$2y$10$AfoOl/0A4uwCPWsXczLvpe3pkVeLnBW.uTU.jwhPOkYmKGtyma5ve');

INSERT INTO `auth_access` (`user_id`, `permission`) VALUES
(1, 'editor');
