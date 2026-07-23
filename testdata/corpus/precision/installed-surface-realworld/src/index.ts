// Real named imports from the FOUR real-world package shapes installed under
// node_modules/ (each package.json reconstructs the actual current shape of the
// named package — see each node_modules/<pkg>/package.json). Every member below
// is genuinely exported by (or reachable from) its package, so a correct
// resolver produces ZERO `real/nonexistent-api` findings here:
//
//   - drizzle-orm         : exports-map with a sibling `types` + nested
//                           import/require conditions AND a bare-string
//                           `default`; its root re-exports through a >1-level
//                           `export *` chain, so the surface conservatively
//                           degrades to Dynamic (info) — never a false High.
//   - drizzle-orm/pg-core : a SUBPATH resolved via `exports["./pg-core"].types`.
//   - @testing-library/react : SCOPED, NO exports map, classic top-level
//                              `types` re-exporting a foreign package (Dynamic).
//   - @aws-sdk/client-s3  : SCOPED, top-level `types`, a one-level relative
//                           barrel that fully resolves (Resolved).
//   - winston            : classic top-level `types` bundled `.d.ts`, plain
//                          declarations (Resolved).
import { eq, and, sql } from 'drizzle-orm';
import { pgTable } from 'drizzle-orm/pg-core';
import { screen, render, fireEvent } from '@testing-library/react';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { format, createLogger, transports } from 'winston';

void eq;
void and;
void sql;
void pgTable;
void screen;
void render;
void fireEvent;
void S3Client;
void GetObjectCommand;
void format;
void createLogger;
void transports;
