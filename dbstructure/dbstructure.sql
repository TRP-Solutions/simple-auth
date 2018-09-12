--
-- Database
--

CREATE DATABASE IF NOT EXISTS `my_db` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
USE `my_db`;

--
-- Tables
--

CREATE TABLE IF NOT EXISTS `auth_access` (
	`user_id` int(10) UNSIGNED NOT NULL,
	`permission` varchar(30) NOT NULL,
	PRIMARY KEY (`user_id`,`permission`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `auth_user` (
	`id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`password` varchar(255) NOT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `username` (`username`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Data
--

INSERT INTO `auth_user` (`id`, `username`, `password`) VALUES
(1, 'johndoe', '$2y$10$AfoOl/0A4uwCPWsXczLvpe3pkVeLnBW.uTU.jwhPOkYmKGtyma5ve');

INSERT INTO `auth_access` (`user_id`, `permission`) VALUES
(1, 'editor');