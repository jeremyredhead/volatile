SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

--
-- Database: `volatile`
--
CREATE DATABASE IF NOT EXISTS `volatile` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `volatile`;

-- --------------------------------------------------------

--
-- Table structure for table `abuser_log`
--

CREATE TABLE `abuser_log` (
  `ip` varchar(255) NOT NULL,
  `timestamp` datetime NOT NULL,
  `count` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `data`
--

CREATE TABLE `data` (
  `key` varchar(255) NOT NULL,
  `val` varchar(255) NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `log`
--

CREATE TABLE `log` (
  `key` varchar(255) NOT NULL,
  `val` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `timestamp` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `read_log`
--

CREATE TABLE `read_log` (
  `key` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `timestamp` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `abuser_log`
--
ALTER TABLE `abuser_log`
  ADD PRIMARY KEY (`ip`);

--
-- Indexes for table `data`
--
ALTER TABLE `data`
  ADD PRIMARY KEY (`key`);
COMMIT;
