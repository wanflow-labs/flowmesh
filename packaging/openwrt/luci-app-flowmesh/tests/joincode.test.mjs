// SPDX-License-Identifier: Apache-2.0
// node --test packaging/openwrt/luci-app-flowmesh/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule } from './luci-shim.mjs';

const joincode = loadModule('flowmesh/joincode.js');

// Shared with the console side (Task 8): {"v":1,"s":"https://mesh.example.com:8443","k":"hskey-abc123"}
const CODE = 'wanflow://eyJ2IjoxLCJzIjoiaHR0cHM6Ly9tZXNoLmV4YW1wbGUuY29tOjg0NDMiLCJrIjoiaHNrZXktYWJjMTIzIn0';
const WANT = { ok: true, server: 'https://mesh.example.com:8443', key: 'hskey-abc123' };

const b64url = (s) => Buffer.from(s, 'utf8').toString('base64url');

// The shape of wanflow-api's buildLinuxInstallScript output (values through escapeshellarg).
const INSTALL = [
	'#!/bin/sh',
	'# Wanflow FlowMesh · Linux 服务器接入脚本',
	'# 订单 #12 · 生成于 2026-10-20 10:00:00',
	"{ curl -fsSL 'https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh' || wget -qO- 'https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh'; } | sh -s -- \\",
	"  --login-server='https://mesh.example.com:8443' \\",
	"  --auth-key='hskey-abc123' \\",
	"  --hostname='web-1' \\",
	'  --advertise-exit-node',
	'',
].join('\n');

test('join code: the shared test vector', () => {
	assert.deepEqual(joincode.parse(CODE), WANT);
});

test('join code: surrounding spaces and newlines are ignored', () => {
	assert.deepEqual(joincode.parse('  \n' + CODE + '  \n'), WANT);
	assert.deepEqual(joincode.parse('\t' + CODE + '\r\n'), WANT);
});

test('join code: padding and the standard base64 alphabet are accepted too', () => {
	const json = '{"v":1,"s":"https://mesh.example.com:8443","k":"hskey-abc123"}';
	assert.deepEqual(joincode.parse('wanflow://' + Buffer.from(json).toString('base64')), WANT);
});

test('join code: a newer version is reported as such', () => {
	assert.deepEqual(joincode.parse('wanflow://eyJ2IjoyLCJzIjoiaHR0cHM6Ly9hLmV4YW1wbGUiLCJrIjoieCJ9'), { ok: false, error: 'version' });
});

test('join code: UTF-8 inside the JSON survives decoding', () => {
	const code = 'wanflow://' + b64url('{"v":1,"s":"https://mesh.example.com","k":"hskey-x","n":"路由器"}');
	assert.deepEqual(joincode.parse(code), { ok: true, server: 'https://mesh.example.com', key: 'hskey-x' });
});

test('install command: --login-server and --auth-key are taken from it', () => {
	assert.deepEqual(joincode.parse(INSTALL), WANT);
});

test('install command: --authkey is accepted as well', () => {
	assert.deepEqual(joincode.parse(INSTALL.replace('--auth-key=', '--authkey=')), WANT);
});

test('install command: unquoted, double-quoted and space-separated values', () => {
	assert.deepEqual(joincode.parse('flowmesh up --login-server=https://mesh.example.com:8443 --auth-key=hskey-abc123'), WANT);
	assert.deepEqual(joincode.parse('sh -s -- --login-server "https://mesh.example.com:8443" --authkey "hskey-abc123"'), WANT);
});

test('install command: one of the two values missing is a format error', () => {
	assert.deepEqual(joincode.parse("sh -s -- --login-server='https://mesh.example.com:8443'"), { ok: false, error: 'format' });
	assert.deepEqual(joincode.parse("sh -s -- --auth-key='hskey-abc123'"), { ok: false, error: 'format' });
	assert.deepEqual(joincode.parse("sh -s -- --login-server='ftp://mesh.example.com' --auth-key='hskey-abc123'"), { ok: false, error: 'format' });
});

test('empty input', () => {
	assert.deepEqual(joincode.parse(''), { ok: false, error: 'empty' });
	assert.deepEqual(joincode.parse('  \n\t'), { ok: false, error: 'empty' });
	assert.deepEqual(joincode.parse(null), { ok: false, error: 'empty' });
	assert.deepEqual(joincode.parse(undefined), { ok: false, error: 'empty' });
});

test('format errors', () => {
	const bad = [
		'hello',
		'wanflow://!!!',
		'wanflow://',
		'wanflow://' + b64url('{"v":1,"s":"https://a.example"}'), // no k
		'wanflow://' + b64url('{"v":1,"k":"hskey-x"}'), // no s
		'wanflow://' + b64url('{"v":1,"s":"","k":"hskey-x"}'),
		'wanflow://' + b64url('{"v":1,"s":"https://a.example","k":7}'),
		'wanflow://' + b64url('{"v":1,"s":"ftp://a.example","k":"hskey-x"}'),
		'wanflow://' + b64url('{"s":"https://a.example","k":"hskey-x"}'), // no v
		'wanflow://' + b64url('{"v":"1","s":"https://a.example","k":"hskey-x"}'),
		'wanflow://' + b64url('{"v":0,"s":"https://a.example","k":"hskey-x"}'),
		'wanflow://' + b64url('[1,2]'),
		'wanflow://' + b64url('null'),
		'wanflow://' + b64url('not json'),
		'wanflow://' + Buffer.from([0xff, 0xfe, 0x7b]).toString('base64url'), // not UTF-8
		'wanflow://abcde', // impossible length
		CODE + ' trailing',
	];
	for (const text of bad) assert.deepEqual(joincode.parse(text), { ok: false, error: 'format' }, text);
});
