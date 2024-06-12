@load base/protocols/conn/removal-hooks

module dnstunnelling;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register dnstunnelling for.
	const ports = {
		# TODO: Replace with actual port(s).
		53/udp, 5353/udp, 53/tcp, 5353/tcp

	} &redef;

	## Record type containing the column fields of the dnstunnelling log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The type of the message
		mtype: string &log;
		## The size of the payload
		len: count &log;
                #A flag byte which can show an anomaly;
		mflags: string &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		#request: string &optional &log;
		## Response-side payload.
		#reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	#global log_policy: Log::PolicyHook;

	## Default hook into dnstunnelling logging.
	global log_dnstunnelling: event(rec: Info);

	## dnstunnelling finalization hook.
	#global finalize_dnstunnelling: Conn::RemovalHook;
}

#redef record connection += {
#	dnstunnelling: Info &optional;
#};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#	{
#	return cat(Analyzer::ANALYZER_DNSTUNNELLING, c$start_time, c$id, is_orig);
#	}

event zeek_init() &priority=5
	{
	#Log::create_stream(dnstunnelling::LOG, [$columns=Info, $ev=log_dnstunnelling, $path="dnstunnelling", $policy=log_policy]);

	Log::create_stream(dnstunnelling::LOG, [$columns=Info, $ev=log_dnstunnelling, $path="dnstunnelling"]);	

	
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNSTUNNELLING, ports);

	# TODO: To activate the file handle function above, uncomment this.
	#Files::register_protocol(Analyzer::ANALYZER_DNSTUNNELLING, [$get_file_handle=dnstunnelling::get_file_handle ]);
	}

# Initialize logging state.
#hook set_session(c: connection)
#	{
#	if ( c?$dnstunnelling )
#		return;
#
#	c$dnstunnelling = Info($ts=network_time(), $uid=c$uid, $id=c$id);
#	Conn::register_removal_hook(c, finalize_dnstunnelling);
#	}

#function emit_log(c: connection)
#	{
#	if ( ! c?$dnstunnelling )
#		return;
#
#	Log::write(dnstunnelling::LOG, c$dnstunnelling);
#	delete c$dnstunnelling;
#	}

# Example event defined in dnstunnelling.evt.
event dnstunnelling::message(c: connection, is_orig: bool, payload: string, flags_data: string)
	{
	#hook set_session(c);
	#local info = c$dnstunnelling;
	
	local msg_type: string;

	if ( is_orig )
	{
		#info$request = payload;
		msg_type = "REQUEST";
	}
	else
	{
		#info$reply = payload;
		msg_type = "REPLY";
	}	
	
	if (flags_data == "-98"){
	if (|payload|>250)
	{
	
	Log::write(dnstunnelling::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $mtype=msg_type, $len=|payload|, $mflags=flags_data]);
	}
	}
}

#hook finalize_dnstunnelling(c: connection)
#	{
#	  TODO: For UDP protocols, you may want to do this after every request
#	  and/or reply.
#	emit_log(c);
#	}
