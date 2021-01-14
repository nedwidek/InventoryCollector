using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;

namespace dev.obx.InventoryCollector
{
    /// <summary>
    /// Driver for SystemInfo. Process args, collect system info, post data. Collected data is dumped to console for debug (TODO: maybe make option).
    /// Arguments are URL of dataloader script (required) and asset tag number (optional).
    /// </summary>
    /// <example>
    /// InventoryCollector.exe https://host.of.inventory.system/path/to/dataloader.php 123456
    /// </example>
    class Program
    {
        static void Main(string[] args)
        {
            // Error out if we have too few or too many args
            if(args.Length > 2 || args.Length == 0)
            {
                Console.WriteLine("Please specify URL.");
                Environment.Exit(1);
            }

            string url = args[0];

            // Error out if the URL is not absolute and well formed.
            if(!Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                Console.WriteLine("Specified URL is malformed.");
                Environment.Exit(1);
            }

            SystemInfo si = new SystemInfo();

            // Did they specify an asset tag?
            if(args.Length == 2)
            {
                si.Asset_tag = args[1];
            }

            // Try to collect the data. Exit if we error.
            try
            {
                si.CollectInfo();
            } catch(Exception e)
            {
                Console.WriteLine("Exception Occurred:\n" + e.ToString());
                Environment.Exit(99);
            }

            // Dump the data to console.
            si.Dump();

            // Post the data to the server.
            si.PostData(url);

        }
    }


    /// <summary>
    /// Class to collect system information and post to dataloader on inventory server. Asset Tag can be specified so that dataloader will use that instead of the system UUID for the asset_tag field in the database.
    /// </summary>
    class SystemInfo
    {
        private String hostname;
        private String serial;
        private String uuid;
        private String os;
        private String os_version;
        private String service_pack;
        private String build_number;
        private String architecture;
        private String installed_memory;
        private String mac_address;
        private String install_date;
        private String manufacturer;
        private String model_sku;
        private String model_name;
        private String ip_address;
        private String public_ip;
        private String asset_tag = null;

        public string Asset_tag { get => asset_tag; set => asset_tag = value; }

        /// <summary>
        /// Post the data to the specified URL. If unsuccessful, sleep 5 minutes and try again (do/until).
        /// </summary>
        /// <param name="url">Absolute and well formed URL of dataloader.</param>
        public void PostData(string url)
        {
            // Base values to post.
            var values = new System.Collections.Specialized.NameValueCollection()
            {
                {"hostname",            hostname },
                {"serial",              serial },
                {"uuid",                uuid },
                {"os",                  os },
                {"os_version",          os_version },
                {"service_pack",        service_pack },
                {"build_number",        build_number },
                {"architecture",        architecture },
                {"installed_memory",    installed_memory },
                {"mac_address",         mac_address },
                {"ip_address",          ip_address },
                {"public_ip",           public_ip },
                {"install_date",        install_date },
                {"manufacturer",        manufacturer },
                {"model_sku",           model_sku },
                {"model_name",          model_name },

            };

            // Add asset tag if it was specified.
            if(asset_tag != null)
            {
                values.Add("asset_tag", asset_tag);
            }

            using (WebClient client = new WebClient())
            {
                Boolean done = false;
                string result = "";

                // Keep trying to post data every 5 minutes until it successfully posts.
                do
                {
                    try
                    {
                        byte[] response = client.UploadValues(url, values);
                        result = System.Text.Encoding.UTF8.GetString(response);
                        done = true;
                    } catch(WebException e)
                    {
                        Console.WriteLine("WebException: " + e.Message);
                        Thread.Sleep(300000);
                    }
                } while (!done);

                Console.WriteLine(result);
            }
        }

        /// <summary>
        /// Dumps the collected data for debug purposes.
        /// </summary>
        public void Dump()
        {
            Console.WriteLine("Asset Tag:         " + asset_tag);
            Console.WriteLine("Hostname:          " + hostname);
            Console.WriteLine("Serial Number:     " + serial);
            Console.WriteLine("UUID:              " + uuid);
            Console.WriteLine("OS:                " + os);
            Console.WriteLine("OS Version:        " + os_version);
            Console.WriteLine("Service Pack:      " + service_pack);
            Console.WriteLine("Build Number:      " + build_number);
            Console.WriteLine("Architecture:      " + architecture);
            Console.WriteLine("Installed Memory:  " + installed_memory);
            Console.WriteLine("MAC Address:       " + mac_address);
            Console.WriteLine("Ip Address         " + ip_address);
            Console.WriteLine("Public IP Address: " + public_ip);
            Console.WriteLine("Install Date:      " + install_date);
            Console.WriteLine("Manufacturer:      " + manufacturer);
            Console.WriteLine("Model SKU:         " + model_sku);
            Console.WriteLine("Model Name:        " + model_name);
        }

        /// <summary>
        /// Collect the required system info. TODO: Could use some cleanup/streamlining.
        /// </summary>
        public void CollectInfo()
        {
            ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject service in s.Get())
            {
                foreach (PropertyData property in service.Properties)
                {
                    switch(property.Name)
                    {
                        case "Vendor":
                            this.manufacturer = (String)property.Value;
                            break;
                        case "Name":
                            this.model_sku = (String)property.Value;
                            break;
                        case "Version":
                            this.model_name = (String)property.Value;
                            break;
                        case "IdentifyingNumber":
                            this.serial = (String)property.Value;
                            break;
                        case "UUID":
                            this.uuid = (String)property.Value;
                            break;
                        case "":
                            break;
                    }
                }
            }

            s = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (ManagementObject service in s.Get())
            {
                foreach (PropertyData property in service.Properties)
                {
                    switch (property.Name)
                    {
                        case "Caption":
                            this.os = (String)property.Value;
                            break;
                        case "CSName":
                            this.hostname = (String)property.Value;
                            break;
                        case "Version":
                            this.os_version = (String)property.Value;
                            break;
                        case "OSArchitecture":
                            this.architecture = (String)property.Value;
                            break;
                        case "InstallDate":
                            try
                            {
                                DateTime dt = DateTime.ParseExact(((String)property.Value).Substring(0, 14), "yyyyMMddHHmmss", null);
                                this.install_date = dt.ToString("yyyy-MM-dd HH:mm:ss");
                            } catch(Exception e)
                            {
                                Console.WriteLine("Exception parsing: " + property.Value);
                                Console.WriteLine(e.Message);
                            }
                            break;
                        case "ServicePackMajorVersion":
                            this.service_pack = ((UInt16)property.Value).ToString();
                            break;
                        case "BuildNumber":
                            this.build_number = (String)property.Value;
                            break;
                        case "TotalVisibleMemorySize":
                            UInt64 mem = (ulong)property.Value;
                            mem *= 1024;
                            this.installed_memory = mem.ToString();
                            break;
                    }
                }
            }

            // Get the MAC address of the first NIC.
            var macAddress =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet && !nic.Description.Contains("Loopback") && !nic.Description.Contains("Virtual")
                    select nic.GetPhysicalAddress().ToString()
                ).FirstOrDefault();
            this.mac_address = macAddress;

            // Get the IPv4 address of this computer.
            IPInterfaceProperties ipProperties =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet && !nic.Description.Contains("Loopback") && !nic.Description.Contains("Virtual") && nic.Supports(NetworkInterfaceComponent.IPv4) == true
                    select nic.GetIPProperties()
                ).FirstOrDefault();
            
            foreach (UnicastIPAddressInformation addr in ipProperties.UnicastAddresses)
            {
                if(addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                this.ip_address = addr.Address.ToString();
            }

            // Get the traceroute to Google DNS and then get the first public subnet IPv4 address.
            Traceroute traceroute = new Traceroute("8.8.8.8");
            List<IPAddress> trace = traceroute.GetTrace();
            foreach (IPAddress addr in trace)
            {
                if (addr.ToString().Equals("0.0.0.0")) continue;

                int[] parts = addr.ToString().Split('.').Select(st => int.Parse(st)).ToArray();

                if(  parts[0] == 10 ||
                    (parts[0] == 192 && parts[1] == 168) ||
                    (parts[0] == 172 && (parts[1] >= 16 && parts[1] <= 31)))
                {
                    // private subnet, try next
                    continue;
                }

                // Found the first public subnet address, set it and break out of loop 
                public_ip = addr.ToString();
                break;
            }
        }
    }
}
