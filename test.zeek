#check http sessions and if a source IP is related to three diffrent user-agents or more
#output "xxx.xxx.xxx.xxx is a proxy" where xxx.xxx.xxx.xxx is the source IP

global agts: table[addr] of set[string] = table();

event http_entity_data(c:connection,is_orig:bool,length:count,data:string) 
{
	local sip: addr = c$id$orig_h;
	local agt: string = c$http$user_agent;
        if (sip in agts) 
        {
            add (agts[sip])[agt];
        } 
        else 
        {
            agts[sip] = set(agt);
        }
}

event zeek_done() 
{
    for (i in agts) 
    {
        if (|agts[i]| >= 3) 
        {
            print(i+" is a proxy");
        }
    }
}
