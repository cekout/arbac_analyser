import sys
import time


# used to obtain a dict (<user>:<roles>) from ua
def build_dict_from_pairs(pairs):
    ret_dict = {}
    for pair in pairs:
        if pair[0] in ret_dict:
            ret_dict[pair[0]].append(pair[1])
        else:
            ret_dict[pair[0]] = [pair[1]]
    return ret_dict

#####################################################################

#config is ua, return list of users that can obtain the role r_t of ca
def can_apply_ca(config, ca):
    #check if ra exist
    ra_finded = False
    for ua_pair in config:
        if (ua_pair[1] == ca[0]):
            ra_finded = True
    if (not ra_finded):
        return []
    #build a user:roles dict
    ua_dict = build_dict_from_pairs(config)
    #find users which satisfy r_p and r_n
    users_satisfy = []
    for user in ua_dict:
        flag = True
        #check if user satisfy r_p
        for r_p in ca[1]:
            if (r_p not in ua_dict[user]):
                flag = False

        #check if user satisfy r_n
        for r_n in ca[2]:
            if (r_n in ua_dict[user]):
                flag = False

        #check if user already has r_t
        if (ca[-1] in ua_dict[user]):
            flag = False

        if flag:
            users_satisfy.append(user)
    return users_satisfy

#####################################################################

#config is ua, return list of users to whome the role r_t (of the cr) can be revoked
def can_apply_cr(config, cr):
    #check if ra exist
    ra_finded = False
    for ua_pair in config:
        if (ua_pair[1] == cr[0]):
            ra_finded = True
    if (not ra_finded):
        return []
    else:
        # for each pair <user,role>, check if role is r_t, if true, return user
        ret_users = []
        for pair in config:
            if pair[1] == cr[1]: ret_users.append(pair[0])
        return ret_users

#giving a list of configuration, check if in one of them a user has the role goal_role
def reached_goal_multiple(configurations, goal_role):
    for config in configurations:
        for user_role in config:
            if (user_role[1] == goal_role): return True
    return False


###################################################################################################

#policy initialization
roles = []
users = []
ua = []
cr = []
ca = []
goal = ""

#policy parsing
for line in sys.stdin:
    if (line[0:5] == "Roles"):
        roles = line.split(" ")[1:-1]
    elif (line[0:5] == "Users"):
        users = line.split(" ")[1:-1]
    elif(line[0:2] == "UA"):
        for ua_pair in line.split(" ")[1:-1]:
            ua.append([ua_pair.split(",")[0][1:],ua_pair.split(",")[1][:-1]])
    elif(line[0:2] == "CR"):
        for cr_pair in line.split(" ")[1:-1]:
            cr.append([cr_pair.split(",")[0][1:],cr_pair.split(",")[1][:-1]])
    elif(line[0:2] == "CA"):
        for ca_tuple in line.split(" ")[1:-1]:
            splitted_tuple = ca_tuple.split(",")
            r_a = splitted_tuple[0][1:]
            r_t = splitted_tuple[2][:-1]
            r_p = []
            r_n = []
            if (splitted_tuple[1] != "TRUE"): #if the second element of the tuple is TRUE then r_p and r_n are empty
                for r in splitted_tuple[1].split("&"):
                    if (r[0] == "-"): #if the role start with '-' then it goes into r_n
                        r_n.append(r[1:])
                    else:
                        r_p.append(r)
            ca.append([r_a,r_p,r_n,r_t])
    elif(line[0:4] == "Goal"):
        goal = line.split(" ")[1]

#####################################################################
#apply backward slicing
#start from {goal}
backward_states = [goal]

#flag is setted to false when an iteration doesn't change backward_states
flag = True
while(flag):
    new_backward_states = backward_states
    for ca_tuple in ca:
        #check if there are cas that assign roles contained in backwars_states
        if (ca_tuple[-1] in backward_states):
            # make union of back new_backward_states and r_a, r_p, r_n of the ca
            new_backward_states = list(set(new_backward_states) | {ca_tuple[0]} | set(ca_tuple[1]) | set(ca_tuple[2]))
    #if something changed
    if (new_backward_states != backward_states):
        backward_states = new_backward_states
    else:
        flag = False

#remove from ca rules that assign a role in R\S*, i.e. a role not in backward_states
ca_new = []
for ca_tuple in ca:
    if ca_tuple[-1] in backward_states:
        ca_new.append(ca_tuple)
ca = ca_new

#remove from cr rules cr_tuplethat revoke a role in R\S*
cr_new = []
for cr_tuple in cr:
    if cr_tuple[-1] in backward_states:
        cr_new.append(cr_tuple)
cr = cr_new

roles = backward_states

#####################################################################

##apply forward slicing
#
##initialize S_0
#forward_states = []
#for ua_pair in ua:
#    forward_states.append(ua_pair[1])
#
#forward_states = list(set(forward_states))
#
#flag = True
#while(flag):
#    new_forward_states = forward_states
#    for ca_tuple in ca:
#        #check if the roles in r_p and r_a of the ca are in forward_states (S_i-1)
#        inclusion_satisfied = True
#        for role in ( [ca_tuple[0]] + ca_tuple[1] ):
#            if not(role in forward_states):
#                inclusion_satisfied = False
#        if (inclusion_satisfied):
#            new_forward_states = list(set(new_forward_states) | {ca_tuple[-1]})
#    if (set(new_forward_states) != set(forward_states)):
#        forward_states = new_forward_states
#    else:
#        flag = False
#
##remove from ca rules that include in r_p a role in R\S*
#ca_new = []
#for ca_tuple in ca:
#    flag = True
#    for rp_role in ca_tuple[1]:
#        if not (rp_role in forward_states):
#            flag = False
#    if flag:
#        ca_new.append(ca_tuple)
#ca = ca_new
#
##remove from cr rules that mention a role in R\S*
#cr_new = []
#for cr_tuple in cr:
#    if cr_tuple[0] in forward_states and cr_tuple[1] in forward_states:
#        cr_new.append(cr_tuple)
#cr = cr_new
#
##remove the role R\S* from the negative preconditions of all rule
#for ca_tuple in ca:
#    rn_new = []
#    for rn_role in ca_tuple[2]:
#        if rn_role in forward_states:
#            rn_new.append(rn_role)
#    ca_tuple[2] = rn_new
#
#roles = forward_states

#####################################################################

visited_configurations = []
visited_configurations.append(set(tuple(item) for item in ua))
current_configurations = []
current_configurations.append(ua)

#set a timeout of 10 second (naif method, around 10 seconds)
timeout = time.time()+10
start_time = time.time()

#stop cycling if goal_role is reached from one of the visited configuration
# or if there is no new configuration to visit
# or if time exceded
while (not reached_goal_multiple(current_configurations,goal) and current_configurations and time.time() < timeout):
    new_current_configurations = []
    for config in current_configurations:
        #for each configuration apply all possible ca
        for ca_to_apply in ca:
            users_to_apply = can_apply_ca(config, ca_to_apply)
            #for each ca apply it to all possible user
            for user in users_to_apply:
                #for each user apply ca adding the new role
                new_config = config.copy()
                new_config.append([user,ca_to_apply[-1]])
                #if the configuration is new (not yet visited), add it to the configurations to visit
                if set(tuple(item) for item in new_config) not in visited_configurations:
                    new_current_configurations.append(new_config)
                    visited_configurations.append(set(tuple(item) for item in new_config))

        for cr_to_apply in cr:
            users_to_apply = can_apply_cr(config, cr_to_apply)
            #for each cr apply it to all possible user
            for user in users_to_apply:
                #for each user apply cr removing the role
                new_config = config.copy()
                new_config.remove([user,cr_to_apply[-1]])
                #if the configuration is new (not yet visited), add it to the configurations to visit
                if set(tuple(item) for item in new_config) not in visited_configurations:
                    new_current_configurations.append(new_config)
                    visited_configurations.append(set(tuple(item) for item in new_config))
    current_configurations = new_current_configurations

print(time.time()-start_time)
print(reached_goal_multiple(current_configurations,goal))