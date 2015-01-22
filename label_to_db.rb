require 'mysql'


begin
    con = Mysql.new 'localhost', 'root', 'cyberaces', 'netflow_db'
    while ((inp = $stdin.gets) != "finished")
	   #split on the commas
	   split_arr = inp.split(",")
	   if (split_arr != []) then  
		  #ip name
		  ip_field = split_arr[0].gsub(/[\'\(\"]/, "");
		  if (ip_field =~/\d+.\d+.\d+/) then
			 #malicious or benign label
			 label = if (split_arr[18] == "RAW_NETFLOW") then "TRUE" else "FALSE" end; 
			 puts ip_field + "," + label
#			 con.query("INSERT INTO `#{ARGV[0]}` (`ip`, `label`) VALUES (INET_ATON(\"#{ip_field}\"), #{label});") 
		  end
	   end
    end

rescue Mysql::Error => e
    puts e.errno
    puts e.error

ensure
    con.close if con
end


