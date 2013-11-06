<?php 
/* App schema generated on: 2012-01-15 12:12:24 : 1326625944*/
class AppSchema extends CakeSchema {
	var $name = 'App';

	function before($event = array()) {
		return true;
	}

	function after($event = array()) {
	}

	var $arps = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'mac' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ip' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $dns_messages = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'hostname' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'cname' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ip' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $emails = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'receive' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'relevance' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'comments' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'username' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'password' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'sender' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'receivers' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'subject' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'mime_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'attach_dir' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'parts' => array('type' => 'string', 'null' => true, 'default' => '\'ALL\''),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $fbchats = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'fbuchat_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'user' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'friend' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'chat' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'duration' => array('type' => 'integer', 'null' => true, 'default' => '0'),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $fbuchats = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'user' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'uid' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $feeds = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'name' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'site' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $ftps = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'username' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'password' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'cmd_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'upload_num' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'download_num' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $groups = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'name', 'unique' => 1)),
		'tableParameters' => array()
	);
	var $httpfiles = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'content_type' => array('type' => 'string', 'null' => true, 'default' => '\'\''),
		'file_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'file_name' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'file_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'file_parts' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'file_stat' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $icmpv6s = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'mac' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ip' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $inputs = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'text', 'null' => false, 'default' => NULL, 'length' => 10),
		'pol_id' => array('type' => 'text', 'null' => false, 'default' => NULL, 'length' => 10),
		'start_time' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'end_time' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'filename' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'md5' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'sha1' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $ircs = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'cmd_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'channel_num' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $mms = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => '\' \''),
		'from_num' => array('type' => 'string', 'null' => true, 'default' => '\' \''),
		'to_num' => array('type' => 'string', 'null' => true, 'default' => '\' \''),
		'cc_num' => array('type' => 'string', 'null' => true, 'default' => '\' \''),
		'bcc_num' => array('type' => 'string', 'null' => true, 'default' => '\' \''),
		'contents' => array('type' => 'integer', 'null' => true, 'default' => '0'),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $mmscontents = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'mm_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'content_type' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'filename' => array('type' => 'string', 'null' => true, 'default' => '\'No name\''),
		'file_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'file_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $params = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'nvalue' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'svalue' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'name', 'unique' => 1)),
		'tableParameters' => array()
	);
	var $pjls = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'pdf_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'pdf_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'pcl_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'pcl_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'error' => array('type' => 'integer', 'null' => true, 'default' => '0'),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $pols = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'external_ref' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'group_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'realtime' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'raw' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $rtps = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'from_addr' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'to_addr' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ucaller' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ucalled' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'umix' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'duration' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $sips = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'commands' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'from_addr' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'to_addr' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ucaller' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'ucalled' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'umix' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'duration' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $sols = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'start_time' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'end_time' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_start' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_end' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'status' => array('type' => 'string', 'null' => true, 'default' => '\'EMPTY\''),
		'rm' => array('type' => 'integer', 'null' => true, 'default' => '0'),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $sources = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'ip' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $syslogs = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'hosts' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'log' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'log_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $telnets = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'hostname' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'username' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'password' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'cmd' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'cmd_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $tftps = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'cmd_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'upload_num' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'download_num' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $unknows = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'important' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'dst' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'dst_port' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'l7prot' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'file_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'duration' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $users = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'username' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'password' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'email' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'em_checked' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'em_key' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'first_name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'last_name' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'last_login' => array('type' => 'timestamp', 'null' => false, 'default' => '0'),
		'login_num' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'user_type' => array('type' => 'string', 'null' => true, 'default' => '\'NORMAL\''),
		'enabled' => array('type' => 'boolean', 'null' => true, 'default' => 'TRUE'),
		'accept_notes' => array('type' => 'boolean', 'null' => true, 'default' => 'TRUE'),
		'group_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'quota_used' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'username', 'unique' => 1)),
		'tableParameters' => array()
	);
	var $webmails = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'data_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => false, 'default' => '0'),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'receive' => array('type' => 'text', 'null' => true, 'default' => '0'),
		'relevance' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'service' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'messageid' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'sender' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'receivers' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'cc_receivers' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'subject' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'mime_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'txt_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'html_path' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'etype' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
	var $webs = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary', 'length' => 11),
		'sol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'pol_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'source_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'web_id' => array('type' => 'integer', 'null' => true, 'default' => '-1'),
		'capture_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'decoding_date' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
		'viewed_date' => array('type' => 'timestamp', 'null' => false, 'default' => '\'0000-00-00 00:00:00\''),
		'first_visualization_user_id' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'flow_info' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'url' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'relation' => array('type' => 'string', 'null' => true, 'default' => '\'NONE\''),
		'method' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'response' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'agent' => array('type' => 'text', 'null' => true, 'default' => NULL),
		'host' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'content_type' => array('type' => 'string', 'null' => false, 'default' => NULL),
		'rq_header' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'rq_body' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'rq_bd_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'rs_header' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'rs_body' => array('type' => 'string', 'null' => true, 'default' => NULL),
		'rs_bd_size' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array()
	);
}
?>