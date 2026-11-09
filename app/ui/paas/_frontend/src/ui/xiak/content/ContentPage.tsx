"use client";

import { createContext, useCallback, useContext, useId, useImperativeHandle, useLayoutEffect, useMemo, useRef, useState, type ComponentPropsWithoutRef, type ReactNode, type Ref, type RefObject } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, ChevronRight } from "lucide-react";
import { Button } from "../button/Button";
import { ActionMenu, type ActionMenuItem } from "../action-menu/ActionMenu";
import { TableActions } from "../table/TableActions";
import { classNames } from "../utils";
import styles from "./ContentPage.module.css";

type BackAction = { label: string; parentLabel?: string; disabled?: boolean; onClick(): void };
export type PageCommand = ActionMenuItem & { variant?: "primary" | "secondary" | "ghost"; icon?: ReactNode; overflowOnly?: boolean };
type HeaderUtility = ActionMenuItem & { icon: ReactNode };
export type PageCommandsHandle = { focus(actionId?: string): void };
type PageSelection = Omit<ComponentPropsWithoutRef<typeof TableActions>, "triggerRef">;
type PageHeading = { title: string; back?: BackAction; focus?: boolean; scrollKey?: string };
type HeadingContribution = PageHeading & { owner: string };
type HeadingSlot = { target: HTMLDivElement | null; parentLabel?: string; utility?: HeaderUtility; utilityRef: RefObject<HTMLButtonElement | null>; update(value: HeadingContribution): void; remove(owner: string): void };
const HeadingSlotContext = createContext<HeadingSlot | null>(null);
const CommandUtilityContext = createContext<Pick<HeadingSlot, "utility" | "utilityRef"> | null>(null);
const HeaderStateContext = createContext<{ heading: HeadingContribution | null; scrollKey: string | null; pending: boolean; setTarget(target: HTMLDivElement | null): void; setUtilityButton(button: HTMLButtonElement | null): void } | null>(null);
const ScrollPositionContext = createContext<Map<string, number> | null>(null);

function ContentPageRoot({ className, children, parentLabel, utility, pending = false, ...props }: ComponentPropsWithoutRef<"section"> & { parentLabel?: string; utility?: HeaderUtility; pending?: boolean }) {
  const [target, setTarget] = useState<HTMLDivElement | null>(null);
  const [heading, setHeading] = useState<HeadingContribution | null>(null);
  const utilityRef = useRef<HTMLButtonElement>(null);
  const setUtilityButton = useCallback((button: HTMLButtonElement | null) => { utilityRef.current = button; }, []);
  const [positions] = useState(() => new Map<string, number>());
  const remove = useCallback((owner: string) => setHeading((current) => current?.owner === owner ? null : current), []);
  // Only presentation metadata reaches the header. Actions keep their feature
  // providers through a portal; form state never travels through the shell.
  const slot = useMemo(() => ({ target, parentLabel, utility, utilityRef, update: setHeading, remove }), [target, parentLabel, utility, remove]);
  const header = useMemo(() => ({ heading: pending ? null : heading, scrollKey: heading?.scrollKey ?? null, pending, setTarget, setUtilityButton }), [heading, pending, setUtilityButton]);
  return <HeadingSlotContext.Provider value={slot}><HeaderStateContext.Provider value={header}><ScrollPositionContext.Provider value={positions}>
    <section className={classNames(styles.page, className)} {...props}>{children}</section>
  </ScrollPositionContext.Provider></HeaderStateContext.Provider></HeadingSlotContext.Provider>;
}

function HeadingIdentity({ title, back, focus, headingRef }: Omit<PageHeading, "title"> & { title: ReactNode; headingRef?: Ref<HTMLHeadingElement> }) {
  return <div className={styles.identity}>
    {back ? <><Button aria-label={back.label} className={styles.parentLink} disabled={back.disabled} onClick={back.onClick} variant="ghost" size="small"><ArrowLeft aria-hidden="true" /><span>{back.parentLabel ?? back.label}</span></Button><ChevronRight className={styles.separator} aria-hidden="true" /></> : null}
    <h1 key="page-title" className={styles.title} tabIndex={focus ? -1 : undefined} ref={headingRef} title={typeof title === "string" ? title : undefined}>{title}</h1>
  </div>;
}

function Header({ className, title, back, leading, trailing, progress, navigationFocusKey, ...props }: Omit<ComponentPropsWithoutRef<"header">, "children" | "title"> & { title: ReactNode; back?: BackAction; leading?: ReactNode; trailing?: ReactNode; progress?: ReactNode; navigationFocusKey?: string }) {
  const state = useContext(HeaderStateContext);
  const slot = useContext(HeadingSlotContext);
  const utility = slot?.utility;
  const heading = state?.heading;
  const pending = state?.pending ?? false;
  const setTarget = state?.setTarget;
  const titleRef = useRef<HTMLHeadingElement>(null);
  const owner = heading?.owner;
  const focus = heading?.focus;
  const displayedBack = heading ? heading.back : back;
  const safeBack = displayedBack && pending ? { ...displayedBack, disabled: true } : displayedBack;
  useLayoutEffect(() => { if (navigationFocusKey) titleRef.current?.focus({ preventScroll: true }); }, [navigationFocusKey]);
  useLayoutEffect(() => { if (focus) titleRef.current?.focus({ preventScroll: true }); }, [owner, focus]);
  return <header className={classNames(styles.header, className)} {...props}>
    <div className={styles.headerContent}>
      {leading}
      <HeadingIdentity title={heading?.title ?? title} back={safeBack} focus={focus || Boolean(navigationFocusKey)} headingRef={titleRef} />
    </div>
    <div className={styles.headerControls}>
      {setTarget ? <div className={styles.headerActions} hidden={!heading || pending} ref={setTarget} /> : null}
      {trailing ? <div className={styles.headerActions}>{trailing}</div> : null}
      {utility ? <Button ref={state?.setUtilityButton} className={styles.utilityCommand} variant="ghost" size="small" aria-label={utility.label}
        title={utility.disabledReason ?? utility.label} disabled={pending || !commandEnabled(utility)}
        aria-controls={utility.controls} aria-expanded={utility.expanded} onClick={utility.onSelect}>{utility.icon}<span>{utility.label}</span></Button> : null}
    </div>
    {progress}
  </header>;
}

function Heading({ title, back, actions, focus = false, scrollKey }: PageHeading & { actions?: ReactNode }) {
  const slot = useContext(HeadingSlotContext);
  const owner = useId();
  const update = slot?.update;
  const remove = slot?.remove;
  const target = slot?.target;
  const parentLabel = back?.parentLabel ?? slot?.parentLabel;
  const backLabel = back?.label;
  const backDisabled = back?.disabled;
  const onBack = back?.onClick;
  const hasBack = Boolean(onBack);
  const onBackRef = useRef(onBack);
  const invokeBack = useCallback(() => onBackRef.current?.(), []);
  const heading = useRef<HTMLHeadingElement>(null);
  useLayoutEffect(() => { onBackRef.current = onBack; }, [onBack]);
  useLayoutEffect(() => () => remove?.(owner), [remove, owner]);
  useLayoutEffect(() => {
    update?.({ owner, title, focus, scrollKey, back: hasBack && backLabel ? { label: backLabel, parentLabel, disabled: backDisabled, onClick: invokeBack } : undefined });
  }, [update, owner, title, focus, scrollKey, backLabel, parentLabel, backDisabled, hasBack, invokeBack]);
  useLayoutEffect(() => { if (!update && focus) heading.current?.focus({ preventScroll: true }); }, [update, focus]);
  if (!slot) return <header className={styles.standaloneHeading}><HeadingIdentity title={title} back={back} focus={focus} headingRef={heading} />{actions ? <div className={styles.headerActions}>{actions}</div> : null}</header>;
  return target && actions ? createPortal(<CommandUtilityContext.Provider value={slot}>{actions}</CommandUtilityContext.Provider>, target) : null;
}

function commandEnabled(action: ActionMenuItem) {
  return !action.disabled && !action.disabledReason;
}

function CommandButton({ action, primary = false, buttonRef }: { action: PageCommand; primary?: boolean; buttonRef: Ref<HTMLButtonElement> }) {
  return <Button ref={buttonRef} className={styles.directCommand} size="small"
    variant={action.variant ?? (action.danger ? "ghost" : primary ? "primary" : "secondary")} data-danger={action.danger || undefined}
    disabled={!commandEnabled(action)} aria-controls={action.controls} aria-expanded={action.expanded}
    aria-description={action.disabledReason} title={action.disabledReason ?? action.label} onClick={action.onSelect}>{action.icon}<span>{action.label}</span></Button>;
}

// Keep the direct command mounted across sizes so a resize preserves focus.
function Commands({ label, moreLabel = label, primary, secondary = [], selection: requestedSelection, primaryRef, focusRef }: {
  label: string; moreLabel?: string; primary?: PageCommand; secondary?: readonly PageCommand[];
  selection?: PageSelection; primaryRef?: RefObject<HTMLButtonElement | null>; focusRef?: Ref<PageCommandsHandle>;
}) {
  const slot = useContext(CommandUtilityContext);
  const utility = slot?.utility;
  const selection = requestedSelection?.actions.length || requestedSelection?.selectionLabel ? requestedSelection : undefined;
  const loneSecondary = secondary.length === 1 ? secondary[0] : undefined;
  const direct = primary ?? (loneSecondary?.overflowOnly ? undefined : loneSecondary);
  const others = direct && !primary ? [] : secondary;
  const peer = primary && !selection && loneSecondary && commandEnabled(loneSecondary) && !loneSecondary.danger && !loneSecondary.overflowOnly ? loneSecondary : undefined;
  const selectionItems = selection?.actions.map((action, index) => ({
    ...action, separatorBefore: index === 0 || action.separatorBefore, disabled: selection.disabled || action.disabled,
    disabledReason: action.disabledReason ?? (selection.disabled ? selection.hint : undefined),
  })) ?? [];
  const compactItems: ActionMenuItem[] = [...others, ...selectionItems];
  if (selection?.selectionLabel) compactItems.push({ id: "clear-selection", label: selection.clearLabel, separatorBefore: true, disabled: selection.disabled, onSelect: selection.onClear });
  const foldUtility = Boolean(utility && compactItems.length);
  if (utility && foldUtility) compactItems.push({ ...utility, separatorBefore: true });

  const sharedMenu = !selection && !peer && !utility;
  const directButton = useRef<HTMLButtonElement>(null);
  const peerButton = useRef<HTMLButtonElement>(null);
  const selectionButton = useRef<HTMLButtonElement>(null);
  const wideMenu = useRef<HTMLButtonElement>(null);
  const compactMenu = useRef<HTMLButtonElement>(null);
  const wideGroup = useRef<HTMLDivElement>(null);
  useImperativeHandle(focusRef, () => ({ focus(id?: string) {
    const compact = wideGroup.current && getComputedStyle(wideGroup.current).display === "none";
    const menu = compact || sharedMenu ? compactMenu.current : wideMenu.current;
    const main = direct && commandEnabled(direct) ? directButton.current : null;
    const adjacent = !compact && peer ? peerButton.current : null;
    const batch = !compact && !selection?.disabled ? selectionButton.current : null;
    const matches = (item: ActionMenuItem) => item.id === id && commandEnabled(item);
    let target = main ?? adjacent ?? menu ?? batch ?? slot?.utilityRef.current;
    if (utility && matches(utility)) target = compact && foldUtility ? menu : slot?.utilityRef.current;
    else if (id && compact && compactItems.some(matches)) target = menu;
    else if (id && !compact && selectionItems.some(matches)) target = batch;
    else if (id && !compact && others.some(matches)) target = adjacent ?? menu;
    target?.focus({ preventScroll: true });
  } }));

  if (!direct && !compactItems.length) return null;
  let fallback = direct && commandEnabled(direct) ? directButton : slot?.utilityRef;
  if (selection && !selection.disabled) fallback = selectionButton;
  if (!peer && others.length) fallback = wideMenu;
  if (peer) fallback = peerButton;
  return <div className={styles.commandBar} data-fold-utility={foldUtility || undefined}>
    {selection ? <div className={styles.expandedCommands}><TableActions {...selection} triggerRef={selectionButton} fallbackFocusRef={compactMenu} /></div> : null}
    {direct ? <CommandButton action={direct} primary={direct === primary} buttonRef={(element) => {
      directButton.current = element;
      if (primaryRef && primary) primaryRef.current = element;
    }} /> : null}
    <div className={styles.expandedCommands} ref={wideGroup}>
      {peer ? <CommandButton action={peer} buttonRef={peerButton} /> : !sharedMenu && others.length ? <ActionMenu label={moreLabel} actions={others} triggerRef={wideMenu} fallbackFocusRef={compactMenu} size="small" iconOnly /> : null}
    </div>
    {compactItems.length ? <ActionMenu className={sharedMenu ? undefined : styles.overflowCommand} label={sharedMenu ? moreLabel : label}
      actions={compactItems} summary={selection?.selectionLabel} triggerRef={compactMenu} fallbackFocusRef={sharedMenu ? undefined : fallback} size="small" iconOnly /> : null}
  </div>;
}

function Body({ children, className, inactive = false, pending = false, loading, transitionKey, ...props }: ComponentPropsWithoutRef<"div"> & {
  transitionKey?: string;
  inactive?: boolean;
  pending?: boolean;
  loading?: ReactNode;
}) {
  const positions = useContext(ScrollPositionContext);
  const scrollKey = useContext(HeaderStateContext)?.scrollKey;
  const viewport = useRef<HTMLDivElement>(null);
  const positionKey = transitionKey === undefined ? undefined : scrollKey ? `${transitionKey}#${scrollKey}` : transitionKey;
  useLayoutEffect(() => { if (!pending && positionKey !== undefined && viewport.current) viewport.current.scrollTop = positions?.get(positionKey) ?? 0; }, [pending, positionKey, positions]);
  if (transitionKey === undefined) return <div {...props} aria-busy={inactive || props["aria-busy"]} className={classNames(styles.body, className)} inert={inactive || props.inert}>{children}</div>;
  // The viewport is a stable paint/scroll boundary. Route identity belongs to
  // its inner content so a commit resets feature state without flashing a new
  // page-sized background layer.
  const showLoading = pending && loading !== undefined && loading !== null;
  return <div className={styles.stage}>
    <div {...props} ref={viewport} onScroll={(event) => {
      if (!pending && positions) {
        positions.delete(positionKey!);
        positions.set(positionKey!, event.currentTarget.scrollTop);
        if (positions.size > 64) positions.delete(positions.keys().next().value!);
      }
      props.onScroll?.(event);
    }} aria-busy={pending || inactive || props["aria-busy"]} className={classNames(styles.body, className)}>
      <div aria-hidden={pending || undefined} className={styles.content} hidden={pending} inert={pending || inactive} key={transitionKey}>{children}</div>
    </div>
    {showLoading ? <div className={classNames(styles.body, styles.pending)}>{loading}</div> : null}
  </div>;
}

export const ContentPage = Object.assign(ContentPageRoot, { Header, Heading, Commands, Body });
