using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace dev.obx.InventoryCollector
{
    /// <summary>
    /// This class creates an IPv4 traceroute of just host addresses (no timings) between the caller and the destination address.
    /// Any host that does not reply within the timeout of 500ms is added as 0.0.0.0.
    /// </summary>
    public class Traceroute
    {
        private String destination = null;
        private List<IPAddress> trace = new List<IPAddress>();
        private IPStatus status;

        public List<IPAddress> Trace { get => trace; set => trace = value; }

        public string Destination { get => destination; set => destination = value; }

        public IPStatus Status => status;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="Destination">Destination IPv4 address or DNS host.</param>
        public Traceroute(String Destination)
        {
            this.Destination = Destination;
        }

        /// <summary>
        /// Execute and return the trace to the destination.
        /// </summary>
        /// <returns>The list of IPv4 address between caller and destination.</returns>
        public List<IPAddress> GetTrace()
        {
            // Start at TTL = 1 and do not fragment.
            PingOptions pingOpts = new PingOptions(1, true);
            Boolean done = false;
            Ping ping = new Ping();
            PingReply reply;
            // Create a 32 byte payload
            byte[] buffer = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
            byte[] nulladdr = new byte[] { 0, 0, 0, 0 };

            // Stop after done or 64 hops.
            while ( done == false && pingOpts.Ttl <=64 )
            {
                reply = ping.Send(destination, 1000, buffer, pingOpts);

                // Track the last reply status.
                this.status = reply.Status;

                // If reply address is null add 0.0.0.0, else the IPv4 address of the ICMP reply.
                if (reply.Address == null)
                {
                    trace.Add(new IPAddress(nulladdr));
                }
                else
                {
                    trace.Add(reply.Address);
                }
                
                // Catch all statuses for which we need to increment TTL and go again. Default to being done for all other statuses.
                switch (this.status) {
                    case IPStatus.TimedOut:
                    case IPStatus.TtlExpired:
                        pingOpts.Ttl++;
                        break;
                    default:
                        done = true;
                        break;
                }
            }

            return trace;
        }
    }
}