-- 认证配置表
CREATE TABLE `auth_config` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `name` varchar(50) NOT NULL,
    `hash_algorithm` varchar(20) NOT NULL,
    `salt_mode` varchar(10) DEFAULT 'suffix',
    `algorithm_params` json DEFAULT NULL,
    `is_default` tinyint(1) DEFAULT 0,
    `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
    `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `name_unique` (`name`),
    INDEX `idx_default` (`is_default`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户表
CREATE TABLE `mqtt_user` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `username` varchar(100) NOT NULL,
    `password_hash` varchar(255) NOT NULL,
    `salt` varchar(64) DEFAULT NULL,
    `is_superuser` tinyint(1) DEFAULT 0,
    `auth_config_id` int(11) unsigned DEFAULT NULL,
    `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
    `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `last_login` timestamp NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `mqtt_username` (`username`),
    INDEX `idx_superuser` (`is_superuser`),
    INDEX `idx_created_at` (`created_at`),
    INDEX `idx_last_login` (`last_login`),
    INDEX `idx_auth_config` (`auth_config_id`),
    FOREIGN KEY (`auth_config_id`) REFERENCES `auth_config`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `mqtt_acl` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `resource_type` varchar(10) NOT NULL COMMENT 'user, clientid, ip',
    `resource_name` varchar(100) NOT NULL COMMENT 'username or clientid or ip',
    `permission` varchar(5) NOT NULL COMMENT 'allow, deny',
    `action` varchar(10) NOT NULL COMMENT 'publish, subscribe, pubsub, all',
    `topic` varchar(100) NOT NULL COMMENT 'topic filter',
    `ip` varchar(60) DEFAULT NULL COMMENT 'IP restriction',
    `qos` tinyint(1) DEFAULT NULL COMMENT 'QoS level restriction',
    `retain` tinyint(1) DEFAULT NULL COMMENT 'retain message restriction',
    `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
    `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX resource_idx(resource_type, resource_name),
    INDEX topic_idx(topic),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入默认认证配置
INSERT INTO `auth_config` (`id`, `name`, `hash_algorithm`, `salt_mode`, `algorithm_params`, `is_default`) VALUES
(1, 'default', 'bcrypt', 'disable', '{"salt_rounds": 10}', 1),
(2, 'high_security', 'pbkdf2', 'suffix', '{"iterations": 10000, "key_length": 32}', 0),
(3, 'legacy', 'sha256', 'suffix', '{}', 0),
(4, 'plain', 'plain', 'disable', '{}', 0);

-- 插入默认用户（使用明文配置，方便初始化）
INSERT INTO `mqtt_user` (`username`, `password_hash`, `salt`, `is_superuser`, `auth_config_id`) VALUES
('robustmq', 'robustmq@2024', NULL, 1, 4);
