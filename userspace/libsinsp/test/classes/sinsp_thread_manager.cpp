// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <helpers/threads_helpers.h>

TEST(sinsp_thread_manager, remove_non_existing_thread) {
	const sinsp m_inspector;
	const auto& thread_manager_factory = m_inspector.get_thread_manager_factory();
	const auto manager = thread_manager_factory.create();
	constexpr int64_t unknown_tid = 100;
	/* it should do nothing, here we are only checking that nothing will crash */
	manager->remove_thread(unknown_tid);
	manager->remove_thread(unknown_tid);
}

TEST(sinsp_thread_manager, thread_group_manager) {
	const sinsp m_inspector;
	const auto& thread_manager_factory = m_inspector.get_thread_manager_factory();
	const auto manager = thread_manager_factory.create();

	/* We don't have thread group info here */
	ASSERT_FALSE(manager->get_thread_group_info(8).get());

	const auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_pid = 12;
	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	manager->set_thread_group_info(tinfo->m_pid, tginfo);
	ASSERT_TRUE(manager->get_thread_group_info(tinfo->m_pid).get());

	const auto new_tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We should replace the old thread group info */
	manager->set_thread_group_info(tinfo->m_pid, new_tginfo);
	ASSERT_NE(manager->get_thread_group_info(tinfo->m_pid).get(), tginfo.get());
	ASSERT_EQ(manager->get_thread_group_info(tinfo->m_pid).get(), new_tginfo.get());
}

TEST(sinsp_thread_manager, create_thread_dependencies_null_pointer) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo.reset();

	/* The thread info is nullptr */
	EXPECT_THROW(m_inspector.m_thread_manager->create_thread_dependencies(tinfo), sinsp_exception);
}

TEST(sinsp_thread_manager, create_thread_dependencies_invalid_tinfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 4;
	tinfo->m_pid = -1;
	tinfo->m_ptid = 1;

	/* The thread info is invalid we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_FALSE(tinfo->m_tginfo);
}

TEST(sinsp_thread_manager, create_thread_dependencies_tginfo_already_there) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 4;
	tinfo->m_pid = 4;
	tinfo->m_ptid = 1;

	auto tginfo = std::make_shared<thread_group_info>(4, false, tinfo);
	tinfo->m_tginfo = tginfo;

	/* The thread info already has a thread group we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);
}

TEST(sinsp_thread_manager, create_thread_dependencies_new_tginfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51000;
	tinfo->m_ptid = 51001; /* we won't find it in the table, so we will default to 0 */
	tinfo->m_vtid = 20;
	tinfo->m_vpid = 1;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, true, 1, 1);

	ASSERT_EQ(tinfo->m_ptid, 0);
}

TEST(sinsp_thread_manager, create_thread_dependencies_use_existing_tginfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();
	const auto tinfo = threadinfo_factory.create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = 51004; /* we won't find it in the table, so we will default to 1 */

	{
		auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);
		m_inspector.m_thread_manager->set_thread_group_info(tinfo->m_pid, tginfo);
	}

	const auto other_tinfo = threadinfo_factory.create_shared();
	other_tinfo->m_tid = 51003;
	other_tinfo->m_pid = 51003;
	other_tinfo->m_ptid = 51004;

	m_inspector.m_thread_manager->create_thread_dependencies(other_tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 2, false, 2, 2);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_create_thread_dependencies_valid_parent) {
	DEFAULT_TREE

	/* new thread will be a child of p6_t1 */
	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = p6_t1_tid;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);
	ASSERT_EQ(tinfo->m_ptid, p6_t1_tid);
	ASSERT_THREAD_CHILDREN(p6_t1_tid, 1, 1);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_create_thread_dependencies_invalid_parent) {
	DEFAULT_TREE

	/* new thread will be a child of p6_t1 */
	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = 8000;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);
	/* the new parent will be 0 */
	ASSERT_EQ(tinfo->m_ptid, 0);
}

TEST(sinsp_thread_manager, create_thread_dependencies_caches_fdtable_on_non_main_add) {
	// Non-main thread joining an existing group must get its cached
	// m_main_fdtable pointed at the group leader's fdtable. With
	// PPM_CL_CLONE_FILES set (as the kernel driver always does) get_fd_table()
	// walks to the main thread, so the cache must resolve to the leader.
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();

	const auto main_t = threadinfo_factory.create_shared();
	main_t->m_tid = 9000;
	main_t->m_pid = 9000;
	main_t->m_ptid = 9999;  // no parent in table; create_thread_dependencies reparents to 0
	main_t->m_flags = PPM_CL_CLONE_FILES;
	m_inspector.m_thread_manager->create_thread_dependencies(main_t);
	ASSERT_TRUE(main_t->m_tginfo);

	const auto main_fdt = main_t->get_main_fdtable();
	ASSERT_NE(main_fdt, nullptr);

	const auto sub_t = threadinfo_factory.create_shared();
	sub_t->m_tid = 9001;
	sub_t->m_pid = 9000;
	sub_t->m_ptid = 9999;
	sub_t->m_flags = PPM_CL_CLONE_FILES;
	m_inspector.m_thread_manager->create_thread_dependencies(sub_t);
	ASSERT_EQ(sub_t->m_tginfo.get(), main_t->m_tginfo.get());
	ASSERT_EQ(sub_t->m_tginfo->get_thread_count(), 2);

	// Leader did not change, so the main thread's cache must be unaffected and
	// the new thread's cache must resolve to the leader's fdtable.
	EXPECT_EQ(main_t->get_main_fdtable(), main_fdt);
	EXPECT_EQ(sub_t->get_main_fdtable(), main_fdt);
}

TEST(sinsp_thread_manager, create_thread_dependencies_refreshes_group_on_leader_change) {
	// During a /proc scan the non-main thread can be observed before its group
	// leader. When the leader finally arrives it is pushed to the front of the
	// thread list; every existing thread's cached m_main_fdtable must be
	// refreshed to point at the new leader, otherwise plugin reads of
	// `file_descriptors` would see a stale (or null) fdtable.
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();

	// Non-main thread observed first (no leader yet in the group).
	const auto sub_t = threadinfo_factory.create_shared();
	sub_t->m_tid = 8001;
	sub_t->m_pid = 8000;
	sub_t->m_ptid = 8999;
	sub_t->m_flags = PPM_CL_CLONE_FILES;
	m_inspector.m_thread_manager->create_thread_dependencies(sub_t);
	ASSERT_TRUE(sub_t->m_tginfo);
	ASSERT_EQ(sub_t->m_tginfo->get_thread_count(), 1);
	// With CLONE_FILES set and no main thread in the group, get_fd_table()
	// returns nullptr and the cached pointer must be nullptr.
	EXPECT_EQ(sub_t->get_main_fdtable(), nullptr);

	// The leader arrives: is_main_thread() is true so add_thread_to_group
	// pushes it to the front - this is the leader-change branch.
	const auto main_t = threadinfo_factory.create_shared();
	main_t->m_tid = 8000;
	main_t->m_pid = 8000;
	main_t->m_ptid = 8999;
	main_t->m_flags = PPM_CL_CLONE_FILES;
	m_inspector.m_thread_manager->create_thread_dependencies(main_t);
	ASSERT_EQ(main_t->m_tginfo.get(), sub_t->m_tginfo.get());
	ASSERT_EQ(main_t->m_tginfo->get_thread_count(), 2);

	const auto main_fdt = main_t->get_main_fdtable();
	ASSERT_NE(main_fdt, nullptr);
	// The previously-added thread's cached pointer must have been refreshed
	// during the leader-change branch.
	EXPECT_EQ(sub_t->get_main_fdtable(), main_fdt);
}

TEST(sinsp_thread_manager, THRD_MANAGER_find_new_reaper_nullptr) {
	const sinsp m_inspector;
	const auto& thread_manager_factory = m_inspector.get_thread_manager_factory();
	const auto manager = thread_manager_factory.create();
	EXPECT_THROW(manager->find_new_reaper(nullptr), sinsp_exception);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_reaper_in_the_same_thread_group) {
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;

	/* We mark it as dead otherwise it will be chosen as a new reaper */
	const auto p5_t1_tinfo = thread_manager->find_thread(p5_t1_tid, true).get();
	ASSERT_TRUE(p5_t1_tinfo);
	p5_t1_tinfo->set_dead();

	/* Call the find reaper method, the reaper thread should be the unique thread alive in the group
	 */
	const auto reaper = thread_manager->find_new_reaper(p5_t1_tinfo);
	ASSERT_EQ(reaper->m_tid, p5_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_reaper_in_the_tree) {
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;

	const auto p6_t1_tinfo = thread_manager->find_thread(p6_t1_tid, true).get();
	ASSERT_TRUE(p6_t1_tinfo);

	/* Call the find reaper method, the reaper for p6_t1 should be p4_t1  */
	const auto reaper = thread_manager->find_new_reaper(p6_t1_tinfo);
	ASSERT_EQ(reaper->m_tid, p4_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_new_reaper_detect_loop) {
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;

	/* If we detect a loop the new reaper will be nullptr.
	 * We set p2_t1 group as a reaper.
	 */
	const auto p2_t1_tinfo = thread_manager->find_thread(p2_t1_tid, true).get();
	ASSERT_TRUE(p2_t1_tinfo);
	p2_t1_tinfo->m_tginfo->set_reaper(true);

	/* We explicitly set p3_t1 ptid to p4_t1, so we create a loop */
	const auto p3_t1_tinfo = thread_manager->find_thread(p3_t1_tid, true).get();
	ASSERT_TRUE(p3_t1_tinfo);
	p3_t1_tinfo->m_ptid = p4_t1_tid;

	/* We will call find_new_reaper on p4_t1 but before doing this we need to
	 * remove p4_t2 otherwise we will have a valid thread in the same group as a new reaper
	 */
	remove_thread(p4_t2_tid, p4_t1_tid);

	/* We call find_new_reaper on p4_t1.
	 * The new reaper should be nullptr since we detected a loop.
	 */
	const auto p4_t1_tinfo = thread_manager->find_thread(p4_t1_tid, true).get();
	ASSERT_TRUE(p4_t1_tinfo);
	ASSERT_EQ(thread_manager->find_new_reaper(p4_t1_tinfo), nullptr);
}
