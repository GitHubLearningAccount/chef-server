%% -*- erlang-indent-level: 4; indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%%
%% @author Mark Anderson <mark@chef.io>
%% Copyright 2017 Chef Software, Inc.
%%
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
-module(oc_chef_authz_scoped_name_tests).

-compile([export_all]).

-include_lib("eunit/include/eunit.hrl").

-define(M, oc_chef_authz_scoped_name).

-define(GLOBAL_PLACEHOLDER_ORG_ID, <<"00000000000000000000000000000000">>).

-define(ORG1, <<"the_org">>).
-define(ORG1_ID, <<"ORG1_ID_AAAAA">>).
-define(ORG2, <<"organization2">>).
-define(ORG2_ID, <<"ORG2_ID_BBBBB">>).
-define(PLAIN_NAME, <<"name">>).
-define(GLOBAL_NAME, <<"::name">>).
-define(PLAIN_GROUP, <<"a_group">>).
-define(ORGLOCAL_NAME, <<"organization2::name">>).
-define(BARE_ORG_NAME, <<"organization::">>).
-define(DEEP_NAME, <<"foo::bar::baz">>).
-define(INVALID_NAME, <<"foo123AGAc">>).
-define(PLAIN_GROUP_AUTHZ_ID, plain_group_authz_id).
-define(GLOBAL_NAME_AUTHZ_ID, global_name_authz_id).
-define(ORGLOCAL_NAME_AUTHZ_ID, orglocal_name_authz_id).

-define(SCOPE_PERMUTATIONS, [{?ORG1_ID, ?PLAIN_GROUP}, {?ORG2_ID, ?PLAIN_GROUP}, {?GLOBAL_PLACEHOLDER_ORG_ID, ?PLAIN_GROUP}]).


stringtitle(Desc, Args) ->
    erlang:iolist_to_binary(io_lib:format(Desc, Args)).

mk_parse_scoped_name_test(true) ->
    [{?PLAIN_NAME, {{name, ?ORG1}, ?PLAIN_NAME}},
     {?GLOBAL_NAME, {{name, global_org}, ?PLAIN_NAME}},
     {?ORGLOCAL_NAME, {{name, ?ORG2}, ?PLAIN_NAME}},
     {?BARE_ORG_NAME, {bad_name, ?BARE_ORG_NAME}},
     {?DEEP_NAME, {bad_name, ?DEEP_NAME}}];
mk_parse_scoped_name_test(false) ->
    [{?PLAIN_NAME, {{name, ?ORG1}, ?PLAIN_NAME}},
     {?GLOBAL_NAME, {bad_name, ?GLOBAL_NAME}},
     {?ORGLOCAL_NAME, {bad_name, ?ORGLOCAL_NAME}},
     {?BARE_ORG_NAME, {bad_name, ?BARE_ORG_NAME}},
     {?DEEP_NAME, {bad_name, ?DEEP_NAME}}
    ].

parse_scoped_name_test_() ->
    Subject = fun ?M:parse_scoped_name/3,
    TestTuples = lists:flatten( [ [{N, S, R} || {N, R} <- mk_parse_scoped_name_test(S) ] || S <- [true,false] ] ),
    TestFun = fun(Name, ScopedOk, Result) ->
                      Title = stringtitle("Test ~s ~p ~p",[Name, ScopedOk, Result]),
                      {Title,
                       fun() ->
                               Answer = Subject({name, ?ORG1}, Name, ScopedOk),
                               ?assertEqual(Result,  Answer)
                       end
                      }
              end,
    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
              ok
     end,
     [ TestFun(N, S, R) || {N, S, R} <- TestTuples ]
    }.

parse_scoped_names_test_() ->
    Subject = fun ?M:parse_scoped_names/3,
    TestFun = fun(Scoped) ->
                      Title = stringtitle("~s",[Scoped]),
                      {Title,
                       fun() ->
                               Data = mk_parse_scoped_name_test(Scoped),
                               {Input, Output} = lists:unzip(Data),
                               Answer = Subject({name, ?ORG1}, Input, Scoped),
                               ?assertEqual(Output,  Answer)
                       end
                      }
              end,

    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [
      ?_assertEqual([{{name, global_org}, <<"name">>}],
                    Subject({name, ?ORG1}, [?GLOBAL_NAME], true))
      | [ TestFun(S) || S <- [true, false] ]
     ]
    }.


empty_names_to_authz_id_test() ->
    Context = mk_context(),
    Subject = fun ?M:names_to_authz_id/3,
    Answer = Subject(group, [], Context),
    ?assertEqual({[], []}, Answer).

%%
%% Names to authz id
%%
names_to_authz_id_test_() ->
    Context = mk_context(),
    Subject = fun ?M:names_to_authz_id/3,

    {foreach,
     fun() ->
             meck:new(chef_db),
             meck:new(oc_chef_authz_db),
             meck:expect(chef_db, fetch_org_metadata, fun(_,?ORG1) -> {?ORG1_ID, dummyAuthzId} end ),
             meck:expect(oc_chef_authz_db, authz_records_by_name, mock_authz_records_by_name(group, make_simple_authz_record_data()) ),
             ok
     end,
     fun(ok) ->
             meck:unload(oc_chef_authz_db),
             meck:unload(chef_db)
     end,
     [
      {"empty list returns nothing and no errors",
       fun() ->
               Answer = Subject(group, [], Context),
               ?assertEqual({[], []}, Answer)
       end
      },
      {"simple list returns an authz id and no errors",
       fun() ->
               Answer = Subject(group, [?PLAIN_GROUP], Context),
               ?assertEqual({[make_dummy_authz_id(?ORG1, ?PLAIN_GROUP)], []}, Answer)
       end
      }
     ]
    }.


%% scoped_names_to_authz_id_test_() ->
%%     Subject = fun ?M:scoped_names_to_authz_id/4,
%%     {foreach,
%%      fun() ->
%%              meck:new(?M),
%% %             meck:expect(?M),
%%              ok
%%      end,
%%      fun(ok) ->
%%              meck:unload(?M)
%%      end,
%%      [
%%       {"empty list returns nothing and no errors",
%%        ?_assertEqual({[], []},
%%                      Subject(foo, {<<"TESTID">>, []}, {[], []}, {context}))
%%       }
%%      ]
%%     }.


authz_id_to_names_test_() ->
    Context = mk_context_reverse(mk_lookup_map()),
    Subject = fun ?M:authz_id_to_names/3,

    {foreach,
     fun() ->
             meck:new(chef_sql),
             meck:new(oc_chef_authz_db),
             meck:expect(chef_sql, fetch_org_metadata, fun(?ORG1) -> {?ORG1_ID, dummyAuthzId} end ),
             meck:expect(oc_chef_authz_db, authz_records_by_name, mock_authz_records_by_name(group, make_simple_authz_record_data()) ),
             ok
     end,
     fun(ok) ->
             meck:unload(oc_chef_authz_db),
             meck:unload(chef_sql)
     end,
     [
      {"empty list returns nothing and no errors",
       fun() ->
               Answer = Subject(group, [], Context),
               ?assertEqual({[], []}, Answer)
       end
      },
      {"simple list returns an id and no errors",
       fun() ->
               Answer = Subject(group, [?PLAIN_GROUP_AUTHZ_ID], Context),
               ?assertEqual({[?PLAIN_GROUP], []}, Answer)
       end
      },
      {"long list list returns an id and no errors",
       fun() ->
               Answer = Subject(group, [?PLAIN_GROUP_AUTHZ_ID, ?ORGLOCAL_NAME_AUTHZ_ID, ?GLOBAL_NAME_AUTHZ_ID], Context),
               ?assertEqual({[?PLAIN_GROUP], []}, Answer)
       end
      }
     ]
    }.

query_and_diff_authz_ids_test_() ->
    Subject = fun ?M:query_and_diff_authz_ids/3,

    LookupMap = mk_lookup_map(),
    DbCallback = mk_db_callback_fn(LookupMap),

    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [
      {"empty list returns nothing and no errors",
       fun() ->
               Answer = Subject(dummy_query, [], DbCallback),
               ?assertEqual({[], []}, Answer)
       end
      },
      {"simple list returns and and no errors",
       fun() ->
               Answer = Subject(dummy_query, [?PLAIN_GROUP_AUTHZ_ID], DbCallback),
               ?assertEqual({[{?ORG1_ID, ?PLAIN_GROUP}],[]}, Answer)
       end
      },
      {"longer list returns and and no errors",
       fun() ->
               Answer = Subject(dummy_query, [?PLAIN_GROUP_AUTHZ_ID, ?ORGLOCAL_NAME_AUTHZ_ID, ?GLOBAL_NAME_AUTHZ_ID], DbCallback),
               ?assertEqual({?SCOPE_PERMUTATIONS,[]}, Answer)
       end
      }
     ]
    }.

%%
%%
render_names_in_context_test_() ->
    Context = mk_context_reverse(mk_lookup_map()),
    Subject = fun ?M:render_names_in_context/3,

    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [
      {"empty list returns nothing and no errors",
       fun() ->
               Answer = Subject(?ORG1_ID, [], Context), 
               ?assertEqual([], Answer)
       end
      },
      {"simple list returns and and no errors",
       fun() ->
               Answer = Subject(?ORG1_ID, [{?ORG1_ID,?PLAIN_GROUP}], Context),
               ?assertEqual([?PLAIN_GROUP], Answer)
       end
      },
      {"longer list returns and and no errors",
       fun() ->
               Answer = Subject(?ORG1_ID, ?SCOPE_PERMUTATIONS, Context),
               ?assertEqual([?M:make_name(<<"NONE-ORG2_ID_BBBBB">>,?PLAIN_GROUP),?PLAIN_GROUP,
                             ?M:make_name(<<>>,?PLAIN_GROUP)],
                            Answer)
       end
      }
     ]
    }.


%%
%% Utility functions
%%

mk_db_callback_fn(Map) ->
    fun({_QueryName, [Ids]}) ->
            R = [ X ||  X <- [maps:get(Id, Map, {}) || Id <- Ids], is_list(X)],
            R

    end.

mk_lookup_map() ->
    #{
       ?PLAIN_GROUP_AUTHZ_ID => make_db_record(?PLAIN_GROUP, ?ORG1_ID, ?PLAIN_GROUP_AUTHZ_ID),
       ?ORGLOCAL_NAME_AUTHZ_ID => make_db_record(?PLAIN_GROUP, ?ORG2_ID, ?ORGLOCAL_NAME_AUTHZ_ID),
       ?GLOBAL_NAME_AUTHZ_ID => make_db_record(?PLAIN_GROUP, ?GLOBAL_PLACEHOLDER_ORG_ID, ?GLOBAL_NAME_AUTHZ_ID)
     }.

mk_context() ->
    ?M:initialize_context(?ORG1,?ORG1_ID, db_context, db_callback_fun).

mk_context_reverse(Map) ->
    Callback = mk_db_callback_fn(Map),
    ?M:initialize_context(?ORG1,?ORG1_ID, db_context, Callback).


make_dummy_authz_id(Org, Name) ->
    <<"AUTHZ_", Org/binary, "__", Name/binary>>.

make_dummy_authz_record_2(Org, Name) ->
    {Name, make_dummy_authz_id(Org,Name)}.

mock_authz_records_by_name(group, Map) ->
    fun(group, OrgId, Names) ->
            lists:foldl(fun(N, A) ->
                                case maps:find(OrgId, Map) of
                                    error -> A;
                                    {ok, NMap} ->
                                        case maps:find(N, NMap) of
                                            error -> A;
                                            {ok, AuthzId} -> [AuthzId | A ]
                                        end
                                end
                        end,
                        [], Names)
    end.

make_simple_authz_record_data() ->
    #{ ?ORG1_ID =>
           #{ ?PLAIN_GROUP => make_dummy_authz_record_2(?ORG1,?PLAIN_GROUP) },
       ?GLOBAL_PLACEHOLDER_ORG_ID =>
           #{ ?PLAIN_NAME => make_dummy_authz_record_2(<<"global">>,?PLAIN_NAME )} }.

make_db_record(Name, AuthzId) ->
    [{<<"name">>, Name}, {<<"authz_id">>, AuthzId}].

make_db_record(Name, OrgId, AuthzId) ->
    [{<<"org_id">>, OrgId}, {<<"group_name">>, Name}, {<<"authz_id">>, AuthzId}].
