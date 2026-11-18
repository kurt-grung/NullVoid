import { defineHandler } from 'nitro';
import { store } from '../utils/core';
import { orgHeader } from '../utils/enterprise';

export default defineHandler((event) => ({ schedules: store.listSchedules(orgHeader(event)) }));
