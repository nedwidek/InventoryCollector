using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
namespace dev.obx.InventoryCollector
{
    class Program
    {
        static void Main(string[] args)
        {

            if(args.Length != 1)
            {
                Console.WriteLine("Please specify URL.");
                Environment.Exit(1);
            }

            string url = args[0];

            if(!Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                Console.WriteLine("Specified URL is malformed.");
                Environment.Exit(1);
            }

            SystemInfo si = new SystemInfo();

            try
            {
                si.CollectInfo();
            } catch(Exception e)
            {
                Console.WriteLine("Exception Occurred:\n" + e.ToString());
            }

            si.Dump();

            si.PostData(url);

        }
    }

    class SystemInfo
    {
        String hostname;
        String serial;
        String uuid;
        String os;
        String os_version;
        String service_pack;
        String build_number;
        String architecture;
        String installed_memory;
        String mac_address;
        String install_date;
        String manufacturer;
        String model_sku;
        String model_name;

        public void PostData(string url)
        {
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
                {"install_date",        install_date },
                {"manufacturer",        manufacturer },
                {"model_sku",           model_sku },
                {"model_name",          model_name },

            };

            using (WebClient client = new WebClient())
            {
                byte[] response = client.UploadValues(url, values);
                string result = System.Text.Encoding.UTF8.GetString(response);

                Console.WriteLine(result);
            }
        }

        public void Dump()
        {
            Console.WriteLine("Hostname:         " + hostname);
            Console.WriteLine("Serial Number:    " + serial);
            Console.WriteLine("UUID:             " + uuid);
            Console.WriteLine("OS:               " + os);
            Console.WriteLine("OS Version:       " + os_version);
            Console.WriteLine("Service Pack:     " + service_pack);
            Console.WriteLine("Build Number:     " + build_number);
            Console.WriteLine("Architecture:     " + architecture);
            Console.WriteLine("Installed Memory: " + installed_memory);
            Console.WriteLine("MAC Address:      " + mac_address);
            Console.WriteLine("Install Date:     " + install_date);
            Console.WriteLine("Manufacturer:     " + manufacturer);
            Console.WriteLine("Model SKU:        " + model_sku);
            Console.WriteLine("Model Name:       " + model_name);
        }

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

            var macAddress =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet && !nic.Description.Contains("Loopback") && !nic.Description.Contains("Virtual")
                    select nic.GetPhysicalAddress().ToString()
                ).FirstOrDefault();
            this.mac_address = macAddress;
        }
    }
}
