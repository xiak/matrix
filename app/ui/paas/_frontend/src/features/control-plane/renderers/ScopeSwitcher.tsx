"use client";

import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { ChevronDown, Layers3, MapPin, ShieldCheck } from "lucide-react";
import { Button, Select } from "@ui/xiak";
import type { ConsoleScopeScene } from "../scenes/consoleScene";
import { HeaderPopover, HeaderPopoverHeader } from "./HeaderPopover";
import styles from "./ScopeSwitcher.module.css";

type ScopeSelectionProps = Readonly<{
  onProjectChange(value: string): void;
  onRegionChange(value: string): void;
  projectId: string;
  regionId: string;
  scope: ConsoleScopeScene;
}>;

export function HeaderScopeControls({ onProjectChange, onRegionChange, projectId, regionId, scope }: ScopeSelectionProps) {
  return (
    <div aria-label="全局资源范围" className={styles.headerControls}>
      <span className={styles.organization}><ShieldCheck aria-hidden="true" /><span>{scope.organization.name}</span></span>
      <label>
        <span>项目</span>
        <select aria-label="选择项目范围" onChange={(event) => onProjectChange(event.target.value)} value={projectId}>
          {scope.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
        </select>
        <ChevronDown aria-hidden="true" />
      </label>
      <label>
        <span>区域</span>
        <select aria-label="选择区域范围" onChange={(event) => onRegionChange(event.target.value)} value={regionId}>
          {scope.regions.map((region) => <option key={region.id} value={region.id}>{region.name}</option>)}
        </select>
        <ChevronDown aria-hidden="true" />
      </label>
    </div>
  );
}

type CompactScopeSwitcherProps = ScopeSelectionProps & Readonly<{
  onOpenChange(open: boolean): void;
  open: boolean;
}>;

const panelId = "compact-global-scope-switcher";

export function CompactScopeSwitcher({
  onOpenChange,
  onProjectChange,
  onRegionChange,
  open,
  projectId,
  regionId,
  scope
}: CompactScopeSwitcherProps) {
  const trigger = useRef<HTMLButtonElement>(null);
  const projectSelect = useRef<HTMLSelectElement>(null);
  const projectName = scope.projects.find((project) => project.id === projectId)?.name ?? "未指定项目";
  const regionName = scope.regions.find((region) => region.id === regionId)?.name ?? "未指定区域";

  useEffect(() => {
    if (open) projectSelect.current?.focus();
  }, [open]);

  function closeAndRestoreFocus() {
    onOpenChange(false);
    trigger.current?.focus();
  }

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopPropagation();
    closeAndRestoreFocus();
  }

  const actionLabel = `${open ? "关闭" : "打开"}资源范围，项目 ${projectName}，区域 ${regionName}`;

  return (
    <div className={styles.compactRoot}>
      <button
        aria-controls={open ? panelId : undefined}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={actionLabel}
        className={styles.compactTrigger}
        onClick={() => open ? closeAndRestoreFocus() : onOpenChange(true)}
        ref={trigger}
        type="button"
      >
        <Layers3 aria-hidden="true" />
        <span className={styles.summary}>
          <small>资源范围 · {scope.organization.name}</small>
          <strong>{projectName}<span>·</span>{regionName}</strong>
        </span>
        <ChevronDown aria-hidden="true" className={styles.compactChevron} />
      </button>

      {open ? (
        <HeaderPopover align="start" id={panelId} label="资源范围" onKeyDown={handleKeyDown} size="compact">
          <HeaderPopoverHeader
            action={<Button onClick={closeAndRestoreFocus} size="small" variant="ghost">完成</Button>}
            description={scope.organization.name}
            title="资源范围"
          />
          <div className={styles.panelBody}>
            <label className={styles.field}>
              <span><Layers3 aria-hidden="true" />项目</span>
              <Select aria-label="紧凑模式选择项目范围" onChange={(event) => onProjectChange(event.target.value)} ref={projectSelect} value={projectId}>
                {scope.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
              </Select>
            </label>
            <label className={styles.field}>
              <span><MapPin aria-hidden="true" />区域</span>
              <Select aria-label="紧凑模式选择区域范围" onChange={(event) => onRegionChange(event.target.value)} value={regionId}>
                {scope.regions.map((region) => <option key={region.id} value={region.id}>{region.name}</option>)}
              </Select>
            </label>
            <p>资源总览、列表与运行状态会立即按此范围更新。</p>
          </div>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
