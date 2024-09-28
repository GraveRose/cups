##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'CUPS Scanner',
      'Description' => %q{
        This module will check to see if the remote host is vulnerable to CVE-2024-47176. It is required that UDP/631 be allowed to reach the remote host otherwise this module will show that the host is unaffected. In addition, the remote host must be able to send TCP traffic to the local port (LPORT) specified or else this will cause it to fail as well.
      },
        'Author'      => [ 'Grave_Rose' ], # twitter.com/grave_rose
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptAddressLocal.new('LADDR', [ true, 'Local address to listen on', '' ]),
        OptPort.new('LPORT', [ true, 'Local port to listen on', 8080 ]),
        OptAddress.new('RHOST', [ true, 'Remote host to send UDP packet to' ]),
        OptPort.new('RPORT', [ true, 'Remote port to send UDP packet to', 631 ]),
        OptInt.new('TIMEOUT', [ true, 'Timeout in seconds to wait for TCP connection', 5 ])
      ])
  end

  def run
    laddr = datastore['LADDR']
    lport = datastore['LPORT']
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    timeout = datastore['TIMEOUT']

    # Construct the dynamic UDPPACKET
    udp_packet_data = "0 3 http://#{laddr}:#{lport}/printers/whatever"

    # Start the TCP server
    print_status("Starting TCP server on #{laddr}:#{lport}...")

    begin
      tcp_server = Rex::Socket::TcpServer.create(
        'LocalHost' => laddr,
        'LocalPort' => lport,
        'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
      )

      print_good("TCP server started on #{laddr}:#{lport}")

      # Send UDP packet while the TCP server is listening
      send_udp_packet(rhost, rport, udp_packet_data)

      # Wait for a client to connect or timeout
      client = wait_for_tcp_client(tcp_server, timeout)

      if client
        handle_client(client)
      else
        print_error("Timeout reached after #{timeout} seconds, no client connected.")
      end
    rescue ::Exception => e
      print_error("An error occurred: #{e.message}")
    ensure
      tcp_server&.close
      print_status("TCP server closed.")
    end
  end

  def send_udp_packet(rhost, rport, udp_packet_data)
    print_status("Sending UDP packet to #{rhost}:#{rport}...")

    begin
      udp_socket = Rex::Socket::Udp.create(
        'PeerHost' => rhost,
        'PeerPort' => rport,
        'Context'  => { 'Msf' => framework, 'MsfExploit' => self }
      )
      # Correctly send UDP data with `sendto`
      udp_socket.sendto(udp_packet_data, rhost, rport)
      print_good("UDP packet sent to #{rhost}:#{rport}. Data: #{udp_packet_data}")
    rescue ::Exception => e
      print_error("Error sending UDP packet: #{e.message}")
    ensure
      udp_socket&.close
    end
  end

  def wait_for_tcp_client(tcp_server, timeout)
    print_status("Waiting for TCP client connection (timeout: #{timeout} seconds)...")

    begin
      # Use the select method to wait for a client or timeout
      ready = ::IO.select([tcp_server], nil, nil, timeout)
      if ready
        return tcp_server.accept
      else
        return nil
      end
    rescue ::Exception => e
      print_error("Error while waiting for TCP client: #{e.message}")
      return nil
    end
  end

  def handle_client(client)
    print_status("Client connected from #{client.peerhost}:#{client.peerport}")

    # Indicate potential vulnerability
    print_warning("Target #{client.peerhost} is potentially vulnerable!")

    begin
      # Discard any data sent by the client without printing it
      client.recv(4096)  # Receive data but do not process or output it
    rescue ::Exception => e
      # Optionally log errors if needed, but avoid printing any data
      print_error("Error reading data from client: #{e.message}")
    ensure
      # Close the client connection
      client.close
      print_status("Connection closed with client #{client.peerhost}:#{client.peerport}.")
    end
end
