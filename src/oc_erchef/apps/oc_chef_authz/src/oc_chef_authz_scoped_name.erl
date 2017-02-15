%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%%
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@chef.io>
%% Copyright 2016 Chef Software, Inc.
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%

-module(oc_chef_authz_scoped_name).

-include("chef_types.hrl").
-include("oc_chef_types.hrl").

-export([names_to_authz_id/3,
         authz_id_to_names/3]).

-export([make_scoped_names/2,
         parse_scoped_names/2,
         parse_unscoped_names/2,
         convert_ids_to_names/3,
         find_client_authz_ids/2,
         find_user_authz_ids/2,
         find_group_authz_ids/2,

         make_sql_callback/0,
         initialize_context/1,
         initialize_context/2,
         initialize_context/4,
         make_name/2,
         org_id_to_name/1
        ]).

-export([parse_scoped_name/3, fetch_authz_ids/2]).

-ifdef(TEST).
-compile([export_all]).
-endif.

%%
%% Process names with scoping descriptor.
%%

%% This is derived from oc_chef_wm/src/oc_chef_wm_groups.erl; investigate what it will take to refactor this.
-define(NAME, "[a-z0-9\-_]").

-define(SCOPE_SEPARATOR, <<"::">>).
-define(SCOPED_NAME_REGEX, "^(?:(" ?NAME "+)|(?:(" ?NAME "*)\\:\\:(" ?NAME "+)))$").

-record(context, {org_name :: undefined,
                  org_id :: undefined,
                  db_context :: undefined,
                  db_callback_fun :: undefined
                 }).

initialize_context(OrgId) ->
    initialize_context(OrgId, make_sql_callback()).

initialize_context(OrgId, CallBackFun) ->
    initialize_context(undefined, OrgId, undefined, CallBackFun).

initialize_context(OrgName, OrgId, DbContext, undefined) ->
    initialize_context(OrgName, OrgId, DbContext, make_sql_callback());
initialize_context(OrgName, OrgId, DbContext, CallBackFun) ->
    #context{org_name = OrgName, %% TODO Do we use this?
             org_id = OrgId,
             db_context = DbContext,
             db_callback_fun = CallBackFun}.


%%
%% Takes scoped names to authz ids
%%   Names: list of names as binary; can include scoping symbol
%%   Type: The type of object to look for
%%   OrgContext: The name of the org whose context is local or 'global'
%%
%% Output:
%% { [{Name, AuthzId}, [{Name, ErrorType}] }
%%
%%
names_to_authz_id(Type, Names, MapperContext) ->
    %% Lower to fully qualified orgname, name tuples
    ScopedNames = parse_scoped_names(get_org_context(MapperContext), Names, is_scoped_type(Type)),
    {ProperNames, ParseErrors} = lists:foldl(fun filter_parse_errors/2, {[], []}, ScopedNames),

    %% Group by orgname (makes bulk access easier)
    NamesGroupedByOrgNames = group_by_key(lists:sort(ProperNames)),

    %% Map org names to ids
    {NamesGroupedByOrgIds, LookupErrors} = lists:foldl(fun(Name, Acc) -> lookup_org_id(Name, Acc, MapperContext) end,
                                                       {[], ParseErrors}, NamesGroupedByOrgNames),

    %% look them up
    {AuthzIds, NotFound} = lists:foldl(fun(N, A) ->
                                            scoped_names_to_authz_id(Type, N, A, MapperContext)
                                    end,
                                    {[], LookupErrors}, NamesGroupedByOrgIds),
    {lists:flatten(AuthzIds), NotFound}.

get_org_context(#context{org_id = OrgId}) when OrgId =/= undefined ->
    {id, OrgId};
get_org_context(#context{org_name = OrgName}) when OrgName =/= undefined ->
    {name, OrgName}.

filter_parse_errors({bad_name, Name}, {Parsed, Errors}) ->
    {Parsed, [{ill_formed_name, Name} | Errors]};
filter_parse_errors(Name, {Parsed, Errors}) ->
    { [Name | Parsed], Errors }.

%%
lookup_org_id({{id, Id}, Names}, {AccNames, Errors}, _Context) ->
    { [{Id, Names} | AccNames], Errors };
lookup_org_id({{name, global_org}, Names}, {AccNames, Errors}, _Context) ->
    { [{?GLOBAL_PLACEHOLDER_ORG_ID, Names} | AccNames], Errors };
lookup_org_id({{name, OrgName}, Names}, {AccNames, Errors}, #context{org_name = OrgName, org_id = OrgId} ) ->
    { [{OrgId, Names} | AccNames], Errors };
lookup_org_id({{name, OrgName}, Names}, {AccNames, Errors}, #context{}) ->
    case chef_sql:fetch_org_metadata(OrgName) of
        not_found ->
            {AccNames, [{orgname_not_found, OrgName} | Errors]};
         {OrgId, _AuthzId} ->
            {[{OrgId, Names} | AccNames], Errors}
    end.

%%
%% Actually lookup names
%%
scoped_names_to_authz_id(Type, {OrgId, Names}, {AuthzIdAcc, NotFound}, _MapperContext) ->
    Records = oc_chef_authz_db:authz_records_by_name(Type, OrgId, Names),
    FoundNames = lists:sort(names_from_records(Records)),
    GivenNames = lists:sort(Names),
    AuthzIds = ids_from_records(Records),
    case GivenNames -- FoundNames of
        [] ->
            {[AuthzIds| AuthzIdAcc], NotFound };
        RemainingNames ->
            {[AuthzIds| AuthzIdAcc], [{OrgId, RemainingNames} | NotFound ]}
    end.


names_from_records(Records) ->
    [ name_from_record(R) || R  <- Records].

name_from_record({Name, _,  _}) ->
    Name;
name_from_record({Name, _}) ->
    Name.

ids_from_records(Records) ->
    [ id_from_record(R) || R <- Records ].

id_from_record({_, AuthzId}) ->
    AuthzId;
id_from_record({_, UserAuthzId, null}) ->
    UserAuthzId;
id_from_record({_, null, ClientAuthzId}) ->
    ClientAuthzId.

%% Helper functions
%%
%% No error handling; we probably should generate an error when we have missing 
%%
find_client_authz_ids(ClientNames, Context) ->
    {AuthzIds, _Missing} = names_to_authz_id(client, ClientNames, Context),
    AuthzIds.

find_user_authz_ids(UserNames, Context) ->
    {AuthzIds, _Missing} = names_to_authz_id(user, UserNames, Context),
    AuthzIds.

find_group_authz_ids(GroupNames, Context) ->
    {AuthzIds, _Missing} = names_to_authz_id(group, GroupNames, Context),
    AuthzIds.

%%
%%
%%
convert_ids_to_names(ActorAuthzIds, GroupAuthzIds, Context) ->
    {ClientNames, RemainingAuthzIds} = authz_id_to_names(client, ActorAuthzIds,Context),
    {UserNames, DefunctActorAuthzIds} = authz_id_to_names(user, RemainingAuthzIds, Context),
    {GroupNames, DefunctGroupAuthzIds} = authz_id_to_names(group, GroupAuthzIds, Context),
    oc_chef_authz_cleanup:add_authz_ids(DefunctActorAuthzIds, DefunctGroupAuthzIds),
    {ClientNames, UserNames, GroupNames}.

%%
%% Takes authz ids to scoped names
%%
%% Returns {NamesFound, UnmappedAuthzIds} We can have UnmappedAuthzIds if an entity was
%% deleted on the server but not in bifrost, or if we have a mix of clients and users
%%


%%
%% Each type of object has different restrictions on its scope.
%%
authz_id_to_names(group, AuthzIds, #context{org_id = OrgId, db_callback_fun = CallbackFun} = Context) ->
    {ScopedNames, DiffedList} = query_and_diff_authz_ids(find_scoped_group_name_in_authz_ids, AuthzIds, CallbackFun),
    {render_names_in_context(OrgId, ScopedNames, Context), DiffedList};
authz_id_to_names(client, AuthzIds, #context{db_callback_fun = CallbackFun}) ->
    query_and_diff_authz_ids(find_client_name_in_authz_ids, AuthzIds, CallbackFun);
authz_id_to_names(user, AuthzIds, #context{db_callback_fun = CallbackFun}) ->
    query_and_diff_authz_ids(find_user_name_in_authz_ids, AuthzIds, CallbackFun).

query_and_diff_authz_ids(_QueryName, [], _) ->
    %% Sometimes the list of authz ids is empty; shortcut that and save a DB call.
    {[], []};
query_and_diff_authz_ids(QueryName, AuthzIds, CallbackFun) ->
    case CallbackFun({QueryName, [AuthzIds]}) of
        not_found ->
            {[], AuthzIds};
        Results when is_list(Results)->
            {ResultNames, FoundAuthzIds} = lists:foldl(fun extract_maybe_scoped_name/2,
                                                       {[],[]}, Results),
            DiffedList = sets:to_list(sets:subtract(sets:from_list(AuthzIds), sets:from_list(FoundAuthzIds))),
            {lists:reverse(ResultNames), DiffedList};
        _Other ->
            {[], []}
    end.

%extract_maybe_scoped_name([Name, AuthzId],  {Names, AuthzIds}) ->
%    {[Name| Names], [AuthzId | AuthzIds]};
%extract_maybe_scoped_name([OrgId, Name, AuthzId],  {Names, AuthzIds}) ->
%    {[{OrgId, Name} | Names], [AuthzId | AuthzIds]}.

%% Scoped names are triples with org_id, name, and authz_id
extract_maybe_scoped_name([{_NameKey, Name}, {<<"authz_id">>, AuthzId}],
                          {NamesIn, AuthzIdsIn}) ->
    {[Name | NamesIn], [AuthzId | AuthzIdsIn]};
extract_maybe_scoped_name([{<<"org_id">>, OrgId}, {_NameKey, Name}, {<<"authz_id">>, AuthzId}],
                          {NamesIn, AuthzIdsIn}) ->
    {[{OrgId, Name} | NamesIn], [AuthzId | AuthzIdsIn]}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Support routines
%%
is_scoped_type(group) ->
    true;
is_scoped_type(_) ->
    false.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Tools for parsing/unparsing scoped names into {orgname, name} tuples
%% These use a org name as 'context' to resove and emit scoped names
%% Org names are either binaries, or they are the special atom global_org
%%

%% This simplifies testing
make_regex() ->
    {ok, Pattern} = re:compile(?SCOPED_NAME_REGEX),
    Pattern.
%% A scoped name is of the form scope::name. If scope is elided, then we are in the global
%% scope. If there is no scope separator, then it is in the current context.
%% Returns org name, name
%% This introduces a tuple form for names, instead of a simple name, we have a pair {OrgContext, Name}
%% OrgContext is can be a org name, or it can be the special atom 'global_org'
parse_scoped_name(OrgContext, Name, ScopedOk) ->
    Pattern = make_regex(),
    maybe_parse_scoped_name(OrgContext, Name, Pattern, ScopedOk).

parse_scoped_names(OrgContext, Names) ->
    parse_scoped_names(OrgContext, Names, true).

parse_unscoped_names(OrgContext, Names) ->
    parse_scoped_names(OrgContext, Names, false).

parse_scoped_names(OrgContext, Names, ScopedOk) ->
    Pattern = make_regex(),
    [ maybe_parse_scoped_name(OrgContext, Name, Pattern, ScopedOk) || Name <- Names ].

maybe_parse_scoped_name(OrgContext, Name, Pattern, ScopedOk) ->
    process_match(re:run(Name, Pattern, [{capture, all, binary}]), Name, OrgContext, ScopedOk).

%% If no match, then we have an unscoped name, and we use the org context
process_match(nomatch, Name, _OrgContext, _ScopedOk) ->
    {bad_name, Name};
process_match({match, [Name, Name]}, Name, OrgContext, _ScopedOk) ->
    {OrgContext, Name};
%% Anything not a simple, unqualified name should be rejected
process_match({match, _}, Name, _, false) ->
    {bad_name, Name};
%% If scope is omitted, assume global
process_match({match, [_, <<>>, <<>>, Name]}, _, _, true) ->
    {{name, global_org}, Name};
%% Fully qualified name
process_match({match, [_, <<>>, OrgName, Name]}, _, _, true) ->
    {{name, OrgName}, Name}.
%process_match({match,

%%
%% Takes a list of {K, V} pairs, and regroups them. Use maps because the syntax is nice
%%
group_by_key(L) ->
    Map = lists:foldl(fun({K, V}, Map) ->
                              VL = maps:get(K, Map, []),
                              maps:put(K, [V | VL], Map)
                      end,
                      #{}, L),
    maps:to_list(Map).


%%
%%
make_sql_callback() ->
    fun chef_sql:select_rows/1.


%%
%% Helper function for working with unscoped names
%%
make_scoped_names(OrgName, Names) ->
    [{OrgName, Name} || Name <- Names].

%%
%%
%%
fetch_authz_ids(Type, ScopedNames) ->
    NamesByOrg = group_by_key(ScopedNames),
    case fetch_ids_rec(Type, NamesByOrg, {[], []}) of
        [Found, []] ->
            Found;
        [_, Missing] ->
            throw({invalid, Type, Missing})
    end.


%%
%%
%%
fetch_ids_rec(_type, [], {Found, Missing}) ->
    {lists:flatten(Found), Missing};
fetch_ids_rec(Type, [{OrgId, Names} | Remainder], {Found, Missing}) ->
    Records = oc_chef_authz_db:authz_records_by_name(Type, OrgId, Names),
    FoundNames = lists:sort(names_from_records(Records)), % Investigate if this sort is redundant (db may already sort)
    Remaining = Names -- FoundNames, % --/++ on very large lists might be slow.
    Missing1 = case Remaining of
                  [] ->
                      [{OrgId, Remaining} | Missing];
                  _ ->
                      Missing
              end,
    fetch_ids_rec(Type, Remainder, {[FoundNames | Found], Missing1}).


%%
%% Expansion of authz ids into scoped names
%% Takes {OrgName, Name} pairs in ScopedNames and returns
%% list of names with scoping metacharacter inserted
render_names_in_context(OrgId, ScopedNames, Context) ->
    GroupedScopedNames = group_by_key(ScopedNames),
    {Expanded, _Cache} = lists:foldl(fun(E, A) -> render_names_in_context_f(OrgId, E, A) end,
                                     {[], Context}, GroupedScopedNames),
    lists:flatten(Expanded).

%% We are in the same scope, omit qualifier
render_names_in_context_f(OrgId, {OrgId, Names}, {Expanded, Context}) ->
    { [Names | Expanded], Context};
%% we are in a different scope, but it's the global scope. Use abbreviated version.
render_names_in_context_f(_OrgId, {?GLOBAL_PLACEHOLDER_ORG_ID, Names}, {Expanded, Context}) ->
    ENames = [ make_name(<<>>, Name) || Name <- Names],
    { [ENames | Expanded], Context};
render_names_in_context_f(_OrgId, {AnotherOrgId, Names}, {Expanded, Context}) ->
    %% Design note: we drop missing orgs silently. Org deletion leaks many objects and we must
    %% be robust to that.
    case org_id_to_name(AnotherOrgId) of
        not_found ->
            {Expanded, Context};
        OrgName ->
            ENames = [ make_name(OrgName, Name) || Name <- Names ],
            { [ENames, Expanded], Context }
    end.

make_name(OrgName, Name) ->
    <<OrgName/binary, "::", Name/binary>>.


%%
%% Lookup org
%%
org_id_to_name(OrgId) ->
    %% TODO maybe rework this; it bypasses a bunch of our statistics gathering code.
    case chef_sql:select_rows({find_organization_by_id, [OrgId]}) of
        [Org|_Others] ->  proplists:get_value(<<"name">>, Org);
        _ -> not_found
    end.
