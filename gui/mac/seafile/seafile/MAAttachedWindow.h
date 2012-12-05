#import <Cocoa/Cocoa.h>

/*
 Below are the positions the attached window can be displayed at.

 Note that these positions are relative to the point passed to the constructor,
 e.g. MAPositionBottomRight will put the window below the point and towards the right,
      MAPositionTop will horizontally center the window above the point,
      MAPositionRightTop will put the window to the right and above the point,
 and so on.

 You can also pass MAPositionAutomatic (or use an initializer which omits the 'onSide:'
 argument) and the attached window will try to position itself sensibly, based on
 available screen-space.

 Notes regarding automatically-positioned attached windows:

 (a) The window prefers to position itself horizontally centered below the specified point.
     This gives a certain enhanced visual sense of an attachment/relationship.

 (b) The window will try to align itself with its parent window (if any); i.e. it will
     attempt to stay within its parent window's frame if it can.

 (c) The algorithm isn't perfect. :) If in doubt, do your own calculations and then
     explicitly request that the window attach itself to a particular side.
 */

typedef enum _MAWindowPosition {
    // The four primary sides are compatible with the preferredEdge of NSDrawer.
    MAPositionLeft          = NSMinXEdge, // 0
    MAPositionRight         = NSMaxXEdge, // 2
    MAPositionTop           = NSMaxYEdge, // 3
    MAPositionBottom        = NSMinYEdge, // 1
    MAPositionLeftTop       = 4,
    MAPositionLeftBottom    = 5,
    MAPositionRightTop      = 6,
    MAPositionRightBottom   = 7,
    MAPositionTopLeft       = 8,
    MAPositionTopRight      = 9,
    MAPositionBottomLeft    = 10,
    MAPositionBottomRight   = 11,
    MAPositionAutomatic     = 12
} MAWindowPosition;

@interface MAAttachedWindow : NSWindow {
    NSColor *borderColor;
    float borderWidth;
    float viewMargin;
    float arrowBaseWidth;
    float arrowHeight;
    BOOL hasArrow;
    float cornerRadius;
    BOOL drawsRoundCornerBesideArrow;

@private
    NSColor *_MABackgroundColor;
    __weak NSView *_view;
    __weak NSWindow *_window;
    NSPoint _point;
    MAWindowPosition _side;
    float _distance;
    NSRect _viewFrame;
    BOOL _resizing;
}

/*
 Initialization methods

 Parameters:

 view       The view to display in the attached window. Must not be nil.

 point      The point to which the attached window should be attached. If you
            are also specifying a parent window, the point should be in the
            coordinate system of that parent window. If you are not specifying
            a window, the point should be in the screen's coordinate space.
            This value is required.

 window     The parent window to attach this one to. Note that no actual
            relationship is created (particularly, this window is not made
            a childWindow of the parent window).
            Default: nil.

 side       The side of the specified point on which to attach this window.
            Default: MAPositionAutomatic.

 distance   How far from the specified point this window should be.
            Default: 0.
 */

- (MAAttachedWindow *)initWithView: (NSView *)view           // designated initializer
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window
                            onSide: (MAWindowPosition)side
                        atDistance: (float)distance;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window
                        atDistance: (float)distance;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                            onSide: (MAWindowPosition)side
                        atDistance: (float)distance;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                        atDistance: (float)distance;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                            onSide: (MAWindowPosition)side;
- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point;

// Accessor methods
- (NSColor *)borderColor;
- (void)setBorderColor: (NSColor *)value;
- (float)borderWidth;
- (void)setBorderWidth: (float)value;                   // See note 1 below.
- (float)viewMargin;
- (void)setViewMargin: (float)value;                    // See note 2 below.
- (float)arrowBaseWidth;
- (void)setArrowBaseWidth: (float)value;                // See note 2 below.
- (float)arrowHeight;
- (void)setArrowHeight: (float)value;                   // See note 2 below.
- (float)hasArrow;
- (void)setHasArrow: (float)value;
- (float)cornerRadius;
- (void)setCornerRadius: (float)value;                  // See note 2 below.
- (float)drawsRoundCornerBesideArrow;                  // See note 3 below.
- (void)setDrawsRoundCornerBesideArrow: (float)value;   // See note 2 below.
- (void)setBackgroundImage: (NSImage *)value;
- (NSColor *)windowBackgroundColor;                    // See note 4 below.
- (void)setBackgroundColor: (NSColor *)value;

/*
 Notes regarding accessor methods:

 1. The border is drawn inside the viewMargin area, expanding inwards; it does not
    increase the width/height of the window. You can use the -setBorderWidth: and
    -setViewMargin: methods together to achieve the exact look/geometry you want.
    (viewMargin is the distance between the edge of the view and the window edge.)

 2. The specified setter methods are primarily intended to be used _before_ the window
    is first shown. If you use them while the window is already visible, be aware
    that they may cause the window to move and/or resize, in order to stay anchored
    to the point specified in the initializer. They may also cause the view to move
    within the window, in order to remain centered there.

    Note that the -setHasArrow: method can safely be used at any time, and will not
    cause moving/resizing of the window. This is for convenience, in case you want
    to add or remove the arrow in response to user interaction. For example, you
    could make the attached window movable by its background, and if the user dragged
    it away from its initial point, the arrow could be removed. This would duplicate
    how Aperture's attached windows behave.

 3. drawsRoundCornerBesideArrow takes effect when the arrow is being drawn at a corner,
    i.e. when it's not at one of the four primary compass directions. In this situation,
    if drawsRoundCornerBesideArrow is YES (the default), then that corner of the window
    will be rounded just like the other three corners, thus the arrow will be inset
    slightly from the edge of the window to allow room for the rounded corner. If this
    value is NO, the corner beside the arrow will be a square corner, and the other
    three corners will be rounded.

    This is useful when you want to attach a window very near the edge of another window,
    and don't want the attached window's edge to be visually outside the frame of the
    parent window.

 4. Note that to retrieve the background color of the window, you should use the
    -windowBackgroundColor method, instead of -backgroundColor. This is because we draw
    the entire background of the window (rounded path, arrow, etc) in an NSColor pattern
    image, and set it as the backgroundColor of the window.
 */

@end
