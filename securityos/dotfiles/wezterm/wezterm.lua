local wezterm = require 'wezterm'
local config = wezterm.config_builder()

-- Renderer: OpenGL works on real GPUs AND on the live image's Mesa llvmpipe
-- software renderer (the nomodeset / no-GPU boot entries).  WebGpu would need a
-- Vulkan backend that isn't guaranteed on a boot-anywhere image.
config.front_end = 'OpenGL'
config.prefer_egl = true

-- Launch fish (the live user's shell) as a login shell — the account's default
-- shell is bash, so ask for fish explicitly (matches kitty/alacritty).
config.default_prog = { '/run/current-system/profile/bin/fish', '-l' }

-- Disable close confirmation for tabs and window
config.skip_close_confirmation_for_processes_named = {}
config.window_close_confirmation = 'NeverPrompt'

-- Font configuration — fall back through fonts the live image actually ships.
config.font = wezterm.font_with_fallback({ 'Iosevka Term', 'JetBrains Mono', 'DejaVu Sans Mono', 'Terminus' })
config.font_size = 14.0
config.line_height = 1.0

-- Color scheme
config.color_scheme = 'Catppuccin Mocha'
config.colors = {
  background = '#000000', -- True black background
}

-- Background opacity settings
config.window_background_opacity = 0.95
config.macos_window_background_blur = 30

-- Window decoration settings
config.window_decorations = 'RESIZE'
config.window_padding = { left = 5, right = 5, top = 5, bottom = 5 }
config.enable_tab_bar = true
config.use_fancy_tab_bar = false

-- Cursor and animation settings
config.default_cursor_style = 'BlinkingBar'
config.cursor_blink_rate = 500
config.animation_fps = 120
config.max_fps = 144
config.scrollback_lines = 100000
config.use_resize_increments = true

-- Keybindings
local act = wezterm.action
-- Use CTRL|SHIFT so the bare control chars (^T ^Q ^V ^H ^N) stay available to
-- TUI apps (editors, shells, less, …) running inside the terminal.
config.keys = {
  { key = 't', mods = 'CTRL|SHIFT', action = act.SpawnTab 'CurrentPaneDomain' },
  { key = 'q', mods = 'CTRL|SHIFT', action = act.CloseCurrentTab { confirm = false } },
  { key = 'v', mods = 'CTRL|SHIFT', action = act.SplitHorizontal { domain = 'CurrentPaneDomain' } },
  { key = 'h', mods = 'CTRL|SHIFT', action = act.SplitVertical { domain = 'CurrentPaneDomain' } },
  { key = 'n', mods = 'CTRL|SHIFT', action = act.ActivatePaneDirection 'Next' },
  { key = '+', mods = 'CTRL', action = act.IncreaseFontSize },
  { key = '-', mods = 'CTRL', action = act.DecreaseFontSize },
}

-- Enable image display
config.term = 'xterm-256color'

-- Status bar updates
wezterm.on('update-right-status', function(window, pane)
  local workspace = window:active_workspace()
  local pane_info = pane:get_title() or 'unknown'
  window:set_right_status(wezterm.format {
    { Text = 'Workspace: ' .. workspace .. ' | Pane: ' .. pane_info },
  })
end)

-- Visual bell for notifications
config.visual_bell = {
  fade_in_duration_ms = 75,
  fade_out_duration_ms = 75,
  target = 'BackgroundColor',
}

-- Ensure Iosevka is available

return config
